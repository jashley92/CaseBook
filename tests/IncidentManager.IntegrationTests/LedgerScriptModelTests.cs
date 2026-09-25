using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// E-10: deploy/sql/02-Enable-Ledger.sql rebuilds three tables as SQL Server append-only ledger tables with a
/// hard-coded column list. These tests keep that list and the EF model in step, and enforce the ledger's
/// schema rule, so a model change fails here instead of in a customer's upgrade.
/// </summary>
public sealed class LedgerScriptModelTests
{
    private static readonly (string Table, Type Entity)[] LedgerTables =
    [
        ("AuditLog", typeof(AuditLogEntry)),
        ("IntegritySeals", typeof(IntegritySeal)),
        ("ChainOfCustodyEvents", typeof(ChainOfCustodyEvent)),
    ];

    private static string RepoFile(string relative)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) dir = dir.Parent;
        dir.Should().NotBeNull("the tests run inside the repository");
        return File.ReadAllText(Path.Combine(dir!.FullName, relative));
    }

    private static Microsoft.EntityFrameworkCore.Metadata.IModel Model()
    {
        using var conn = new SqliteConnection("Data Source=:memory:");
        using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(conn).Options);
        return db.Model;
    }

    [Fact]
    public void The_ledger_script_lists_exactly_the_columns_the_model_maps()
    {
        var script = RepoFile(Path.Combine("deploy", "sql", "02-Enable-Ledger.sql"));
        var model = Model();

        foreach (var (table, entity) in LedgerTables)
        {
            var m = Regex.Match(script, $@"#AssertColumns N'{table}',\s*N'([^']+)'");
            m.Success.Should().BeTrue($"the script guards {table}");
            var scripted = m.Groups[1].Value.Split(',').Select(c => c.Trim()).OrderBy(c => c).ToList();

            var mapped = model.FindEntityType(entity)!.GetProperties()
                .Select(p => p.GetColumnName()).OrderBy(c => c).ToList();

            mapped.Should().Equal(scripted,
                $"02-Enable-Ledger.sql rebuilds {table} with a fixed column list. If you changed {entity.Name}, update the " +
                "script's #AssertColumns list and its CREATE TABLE and INSERT column lists to match");
        }
    }

    [Fact]
    public void Columns_added_to_ledger_tables_after_launch_are_nullable()
    {
        // SQL Server only allows ADD COLUMN on a ledger table for nullable columns with no default. These are
        // the columns each table shipped with; anything later must be nullable or the upgrade fails on sites
        // that turned the ledger on.
        var original = new Dictionary<string, string[]>
        {
            ["AuditLog"] = ["Id", "Sequence", "AtUtc", "Actor", "Action", "EntityType", "EntityId", "CaseNumber", "Summary",
                            "BeforeJson", "AfterJson", "Reason", "PrevHash", "EntryHash"],
            ["IntegritySeals"] = ["Id", "SealedAtUtc", "UpToSequence", "ChainHeadHash", "Signature", "Algorithm", "KeyId", "SealedBy"],
            ["ChainOfCustodyEvents"] = ["Id", "EvidenceId", "AtUtc", "Actor", "Action", "Details"],
        };
        var model = Model();

        foreach (var (table, entity) in LedgerTables)
        {
            var added = model.FindEntityType(entity)!.GetProperties()
                .Where(p => !original[table].Contains(p.GetColumnName()));
            foreach (var p in added)
                p.IsNullable.Should().BeTrue(
                    $"{table}.{p.GetColumnName()} was added after launch. Ledger tables only accept new nullable columns without a default");
        }
    }

    [Fact]
    public async Task Ledger_status_is_not_applicable_on_sqlite()
    {
        using var conn = new SqliteConnection("Data Source=:memory:");
        conn.Open();
        var factory = new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(conn).Options);
        var status = await new SqlLedgerStatus(factory).GetAsync();
        status.Applicable.Should().BeFalse();
        status.AllOn.Should().BeFalse();
    }
}
