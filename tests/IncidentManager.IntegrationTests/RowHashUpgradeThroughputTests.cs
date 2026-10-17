using System.Diagnostics;
using System.Text.Json;
using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Xunit;
using Xunit.Abstractions;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-644: how fast the integrity upgrade gets through a large database on SQL Server, for the timing docs/UPGRADE.md and
/// docs/architecture/integrity.md give. Two databases of synthetic notes, each with a create and an update entry in the
/// trail: one whose trail already records every hash (as v1.6.12 leaves most records: the upgrade only reads them), and one
/// whose trail records none (as v1.0-v1.5.0 left them: the upgrade records every one). Rows per second go to the test
/// output. <c>CASEBOOK_UPGRADE_ROWS</c> sets the size (default 50,000). Skipped without <c>CASEBOOK_TEST_SQL</c>.
/// </summary>
public sealed class RowHashUpgradeThroughputTests(ITestOutputHelper output)
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };

    private static int Rows =>
        int.TryParse(Environment.GetEnvironmentVariable("CASEBOOK_UPGRADE_ROWS"), out var n) && n > 0 ? n : 50_000;

    [SqlServerFact]
    public async Task The_upgrade_reads_a_recorded_database_and_records_an_older_one_at_a_measured_rate()
    {
        foreach (var recorded in new[] { true, false })
        {
            using var database = TestDatabase.Open(TestDatabase.SqlServer, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
            await using (var db = database.NewContext()) await DevDataSeeder.SeedAsync(db, _clock);
            var seed = Stopwatch.StartNew();
            await SeedNotesAsync(database, Rows, recorded);
            output.WriteLine($"Seeded {Rows:N0} notes ({(recorded ? "trail records their hashes" : "trail records none")}) in {seed.Elapsed.TotalSeconds:N0} s.");

            var run = Stopwatch.StartNew();
            RowHashUpgrade.Result result;
            await using (var db = database.NewContext()) result = await RowHashUpgrade.RunAsync(db, _hasher, _clock);
            run.Stop();
            result.Marked.Should().BeTrue();
            result.Left.Should().BeEmpty();
            if (!recorded) result.Recorded.Should().BeGreaterThanOrEqualTo(Rows);
            var perSecond = Rows / run.Elapsed.TotalSeconds;
            output.WriteLine($"Upgrade ({(recorded ? "read only" : "recording every row")}): {run.Elapsed.TotalSeconds:N1} s, "
                             + $"{perSecond:N0} rows/s, {100_000 / perSecond / 60:N1} min per 100,000 rows.");
        }
    }

    // Notes written outside the interceptor, each with a create and an update entry chained as CaseBook writes them.
    private async Task SeedNotesAsync(TestDatabase database, int count, bool recordHash)
    {
        await using var db = new AppDbContext(database.OptionsWithoutInterceptors);
        db.ChangeTracker.AutoDetectChangesEnabled = false;
        var caseId = await db.Cases.Select(c => c.Id).FirstAsync();
        var head = await db.AuditLog.AsNoTracking().OrderByDescending(a => a.Sequence).FirstAsync();
        const int batch = 2_000;
        for (var done = 0; done < count; done += batch)
        {
            var notes = new List<AnalystNote>();
            var entries = new List<AuditLogEntry>();
            for (var i = done; i < Math.Min(count, done + batch); i++)
            {
                var at = _clock.UtcNow.AddMinutes(-count + i);
                var note = new AnalystNote
                {
                    CaseId = caseId, Body = $"Observed beaconing from host WS-{i:D6} to 203.0.113.{i % 250}; isolated it and pulled the EDR timeline for review.",
                    CreatedBy = "alice", CreatedAtUtc = at,
                };
                note.RowHash = _hasher.ComputeRowHash(note);
                notes.Add(note);
                var created = new Dictionary<string, object?>
                {
                    ["Id"] = note.Id, ["CaseId"] = caseId, ["Body"] = "draft", ["Version"] = 1, ["IsCurrent"] = true,
                    ["MentionsCsv"] = "", ["CreatedBy"] = "alice", ["CreatedAtUtc"] = at,
                };
                var updated = new Dictionary<string, object?> { ["Body"] = note.Body };
                if (recordHash) updated["RowHash"] = note.RowHash;
                foreach (var (action, after) in new[] { (AuditAction.Create, created), (AuditAction.Update, updated) })
                {
                    var entry = new AuditLogEntry
                    {
                        AtUtc = at, Actor = "alice", Action = action, EntityType = nameof(AnalystNote), EntityId = note.Id.ToString(),
                        AfterJson = JsonSerializer.Serialize(after),
                    };
                    _hasher.ChainAppend(entry, head);
                    head = entry;
                    entries.Add(entry);
                }
            }
            db.Notes.AddRange(notes);
            db.AuditLog.AddRange(entries);
            await db.SaveChangesAsync();
            db.ChangeTracker.Clear();
        }
    }
}
