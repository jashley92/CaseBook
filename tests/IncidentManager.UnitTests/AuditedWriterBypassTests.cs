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
}
