using System.Reflection;
using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// C18: a write that goes around the audit interceptor (ExecuteUpdate, ExecuteDelete, raw SQL) leaves no trail and no
/// fresh row hash, so on an audited table it reads as tampering, or worse, changes what a row hash doesn't cover unseen
/// (BUG-630 moved a notice's kept deadline that way, BUG-631 a case's kept jurisdictions). Every such write in src must
/// be on a table the interceptor doesn't audit; raw SQL writes aren't allowed outside migrations. What this can't see: a
/// write through a helper that takes the DbSet as a parameter (none today), or SQL built in a string elsewhere.
/// </summary>
public sealed partial class AuditedWriterBypassTests
{
    [GeneratedRegex(@"\.Execute(?:Update|Delete)(?:Async)?\s*\(", RegexOptions.None, 1000)]
    internal static partial Regex BulkWrite();

    [GeneratedRegex(@"\.ExecuteSql(?:Raw|Interpolated)?(?:Async)?\s*\(", RegexOptions.None, 1000)]
    private static partial Regex RawSqlWrite();

    [GeneratedRegex(@"\b(?:db|raw|recheck|context|ctx|_db)\.(\w+)\b|\.Set<(\w+)>\(\)", RegexOptions.None, 1000)]
    private static partial Regex SetReference();

    /// <summary>Each DbSet property of the context, with the entity it holds.</summary>
    internal static readonly IReadOnlyDictionary<string, Type> Sets = typeof(AppDbContext).GetProperties(BindingFlags.Public | BindingFlags.Instance)
        .Where(p => p.PropertyType.IsGenericType && p.PropertyType.GetGenericTypeDefinition() == typeof(DbSet<>))
        .ToDictionary(p => p.Name, p => p.PropertyType.GetGenericArguments()[0], StringComparer.Ordinal);

    /// <summary>Query helpers a bulk write starts from, with the table each reads (reviewed).</summary>
    private static readonly (string Helper, Type Table)[] Helpers =
    [
        ("VisiblePending(db)", typeof(Domain.Entities.PendingImport)),   // CaseImportService: the import staging queue
    ];

    /// <summary>The entity a bulk write in <paramref name="statement"/> (the text from its start up to the call) acts on,
    /// or null when it names none.</summary>
    internal static Type? Target(string statement)
    {
        foreach (var (helper, type) in Helpers)
            if (statement.Contains(helper, StringComparison.Ordinal)) return type;
        foreach (Match m in SetReference().Matches(statement))
        {
            var name = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
            if (Sets.TryGetValue(name, out var set)) return set;
            if (typeof(Domain.Entities.Case).Assembly.GetType("IncidentManager.Domain.Entities." + name) is { } type) return type;
        }
        return null;
    }

    // The statement a match is in: back to the previous ';', '{' or '}'.
    private static string StatementBefore(string text, int at)
    {
        var start = text.LastIndexOfAny([';', '{', '}'], Math.Max(0, at - 1)) + 1;
        return text[start..at];
    }

    [Theory]
    [InlineData("await db.JurisdictionNotices.Where(x => x.Id == id).ExecuteUpdateAsync(u => u.SetProperty(x => x.DueAtUtc, due), ct);", true)]
    [InlineData("await db.Cases.Where(x => x.Id == c.Id)\n    .ExecuteUpdateAsync(s => s.SetProperty(x => x.ReportedJurisdictions, frozen), ct);", true)]
    [InlineData("db.NotificationMarks.Where(m => m.Key == key).ExecuteDelete();", false)]
    [InlineData("await db.PendingImports.Where(p => p.Id == id).ExecuteUpdateAsync(s => s.SetProperty(p => p.Status, x), ct);", false)]
    public void The_scan_tells_an_audited_table_from_an_unaudited_one(string code, bool audited)
    {
        var m = BulkWrite().Match(code);
        m.Success.Should().BeTrue();
        var target = Target(StatementBefore(code, m.Index));
        target.Should().NotBeNull();
        AuditChainInterceptor.IsAudited(target!).Should().Be(audited);
    }

    [Fact]
    public void No_write_in_src_goes_around_the_audit_on_an_audited_table()
    {
        var src = Path.Combine(ComponentSourceScanner.RepoRoot(), "src");
        var offenders = new List<string>();
        foreach (var path in Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories)
                     .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}Migrations{Path.DirectorySeparatorChar}")
                                 && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                                 && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")))
        {
            var text = File.ReadAllText(path);
            var rel = Path.GetRelativePath(src, path).Replace('\\', '/');
            int Line(int index) => text.AsSpan(0, index).Count('\n') + 1;
            foreach (Match m in BulkWrite().Matches(text))
            {
                var target = Target(StatementBefore(text, m.Index));
                if (target is null) offenders.Add($"{rel}:{Line(m.Index)} bulk write on a table the scan can't name");
                else if (AuditChainInterceptor.IsAudited(target))
                    offenders.Add($"{rel}:{Line(m.Index)} bulk write on {target.Name}, which is audited: write it through EF so it's hashed and recorded");
            }
            foreach (Match m in RawSqlWrite().Matches(text))
                offenders.Add($"{rel}:{Line(m.Index)} raw SQL write outside a migration");
        }
        string.Join("\n", offenders).Should().BeEmpty();
    }

    [GeneratedRegex(@"\b(?:INSERT\s+INTO|DELETE\s+FROM|UPDATE)\s+[\[""]*(\w+)[\]""]*", RegexOptions.IgnoreCase, 1000)]
    private static partial Regex SqlWrite();

    [GeneratedRegex(@"(?:Insert|Update|Delete)Data\s*\(\s*table:\s*""(\w+)""", RegexOptions.None, 1000)]
    private static partial Regex DataOperation();

    /// <summary>Each (migration, table) a released migration writes with SQL or InsertData/UpdateData/DeleteData, in both
    /// providers' migrations, with the file it's in.</summary>
    internal static IEnumerable<(string Migration, string Table, string File)> MigrationWrites()
    {
        var root = ComponentSourceScanner.RepoRoot();
        foreach (var dir in new[] { "src/IncidentManager.Infrastructure/Persistence/Migrations", "src/IncidentManager.Migrations.SqlServer/Migrations" })
            foreach (var path in Directory.EnumerateFiles(Path.Combine(root, dir), "*.cs")
                         .Where(f => !f.EndsWith(".Designer.cs", StringComparison.Ordinal) && !f.EndsWith("ModelSnapshot.cs", StringComparison.Ordinal)))
            {
                var file = Path.GetFileNameWithoutExtension(path);
                var migration = file[(file.IndexOf('_') + 1)..];
                // Up only: Down is never run on a release database.
                var text = File.ReadAllText(path);
                var down = text.IndexOf("void Down(", StringComparison.Ordinal);
                if (down > 0) text = text[..down];
                var sql = text.Replace("\"\"", "\"", StringComparison.Ordinal);
                foreach (Match m in SqlWrite().Matches(sql))
                {
                    var table = m.Groups[1].Value;
                    // "UPDATE q ... FROM [Table] q": the alias's table.
                    if (Regex.Match(sql[m.Index..], $@"FROM\s+[\[""]*(\w+)[\]""]*\s+{Regex.Escape(table)}\b", RegexOptions.None, TimeSpan.FromSeconds(1))
                        is { Success: true } alias) table = alias.Groups[1].Value;
                    yield return (migration, table, Path.GetRelativePath(root, path).Replace('\\', '/'));
                }
                foreach (Match m in DataOperation().Matches(text))
                    yield return (migration, m.Groups[1].Value, Path.GetRelativePath(root, path).Replace('\\', '/'));
            }
    }

    private static readonly Lazy<IReadOnlyDictionary<string, Type>> Tables = new(() =>
    {
        using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite("Data Source=:memory:").Options);
        return db.Model.GetEntityTypes().Where(t => !t.IsOwned() && t.GetTableName() is not null)
            .GroupBy(t => t.GetTableName()!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().ClrType, StringComparer.OrdinalIgnoreCase);
    });

    [Fact]
    public void Every_migration_write_to_an_audited_table_is_listed_with_how_its_rows_are_told_apart(/* C18 */)
    {
        var listed = Application.Integrity.MigrationSeededRows.Writes.Select(w => (w.Migration, w.Table)).ToHashSet();
        var unlisted = new List<string>();
        var seen = new HashSet<(string, string)>();
        foreach (var (migration, table, file) in MigrationWrites())
        {
            if (!Tables.Value.TryGetValue(table, out var type))
            {
                if (table is not ("__EFMigrationsHistory")) unlisted.Add($"{file}: writes {table}, which the model doesn't map");
                continue;
            }
            if (!AuditChainInterceptor.IsAudited(type)) continue;
            seen.Add((migration, table));
            if (!listed.Contains((migration, table)))
                unlisted.Add($"{file}: writes {table} ({type.Name}, audited): list it in MigrationSeededRows with how its rows are told apart");
        }
        string.Join("\n", unlisted).Should().BeEmpty();
        listed.Except(seen).Should().BeEmpty("MigrationSeededRows lists only writes a migration makes");
    }

    [Theory]
    [InlineData("migrationBuilder.Sql(@\"UPDATE \"\"CaseBriefs\"\" SET \"\"IsCurrent\"\" = 0\");", "CaseBriefs")]
    [InlineData("migrationBuilder.Sql(@\"UPDATE q SET q.[Kind] = 0 FROM [StageGateRequirements] q JOIN [StageGates] g ON g.[Id] = q.[GateId]\");", "StageGateRequirements")]
    [InlineData("migrationBuilder.Sql(\"INSERT INTO [ReportTemplates] ([Id]) SELECT [Id] FROM [ReportProfiles]\");", "ReportTemplates")]
    public void The_migration_scan_names_the_table_written(string code, string table)
    {
        var sql = code.Replace("\"\"", "\"", StringComparison.Ordinal);
        var m = SqlWrite().Match(sql);
        var name = m.Groups[1].Value;
        if (Regex.Match(sql[m.Index..], $@"FROM\s+[\[""]*(\w+)[\]""]*\s+{Regex.Escape(name)}\b", RegexOptions.None, TimeSpan.FromSeconds(1))
            is { Success: true } alias) name = alias.Groups[1].Value;
        name.Should().Be(table);
    }
}
