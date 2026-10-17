using System.Diagnostics;
using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;
using Xunit.Abstractions;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// What the 10-minute integrity check costs on a large database on SQL Server, for docs/architecture/integrity.md (Check
/// cost) and the decision on checking only changed records. Synthetic notes and timeline entries (half the steps with a
/// tactic), each with a create and two update entries recording its hash, as CaseBook writes them. Times a full check (the
/// first, and every 6 hours) and an incremental one (every 10 minutes), and the memory the kept state holds, to the test
/// output. <c>CASEBOOK_CHECK_ROWS</c> sets the number of records (default 50,000). Skipped without <c>CASEBOOK_TEST_SQL</c>.
/// </summary>
public sealed class IntegrityCheckThroughputTests(ITestOutputHelper output) : IDisposable
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 16, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };
    private readonly string _workDir = Path.Combine(Path.GetTempPath(), "im-check-throughput", Guid.NewGuid().ToString("N"));

    private static int Rows =>
        int.TryParse(Environment.GetEnvironmentVariable("CASEBOOK_CHECK_ROWS"), out var n) && n > 0 ? n : 50_000;

    public void Dispose()
    {
        try { Directory.Delete(_workDir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    [SqlServerFact]
    public async Task The_check_reads_a_large_database_at_a_measured_rate()
    {
        using var database = TestDatabase.Open(TestDatabase.SqlServer, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
        await using (var db = database.NewContext()) await DevDataSeeder.SeedAsync(db, _clock);
        var seed = Stopwatch.StartNew();
        await SeedAsync(database, Rows);
        output.WriteLine($"Seeded {Rows:N0} records ({Rows * 3:N0} audit entries) in {seed.Elapsed.TotalSeconds:N0} s.");

        var state = new IntegrityCheckState();
        var signer = new RsaSealSigner(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(_workDir, "k.pem"), AllowKeyGeneration = true }));
        var store = new FileSealStore(Options.Create(new SealSigningOptions { ExportPath = Path.Combine(_workDir, "seals") }));
        var svc = new IntegrityService(database.Factory(), _hasher, signer, store, _user, _clock, new IntegrityMonitor(),
            new NoAlerts(), state: state);

        var before = GC.GetTotalMemory(forceFullCollection: true);
        var allocated = GC.GetTotalAllocatedBytes();
        (await svc.MonitorAndTrackAsync()).IsValid.Should().BeTrue();
        var fullAllocated = GC.GetTotalAllocatedBytes() - allocated;
        var full = state.LastCycle!;
        full.Full.Should().BeTrue();
        var kept = GC.GetTotalMemory(forceFullCollection: true) - before;
        Report(full, fullAllocated);

        _clock.UtcNow = _clock.UtcNow.AddMinutes(10);
        allocated = GC.GetTotalAllocatedBytes();
        (await svc.MonitorAndTrackAsync()).IsValid.Should().BeTrue();
        var incremental = state.LastCycle!;
        incremental.Full.Should().BeFalse();
        Report(incremental, GC.GetTotalAllocatedBytes() - allocated);
        output.WriteLine($"Kept between cycles: {kept / 1_048_576.0:N0} MB for {full.RecordsKept:N0} records "
                         + $"({(double)kept / Math.Max(1, full.RecordsKept):N0} bytes each).");
        GC.KeepAlive(state);
    }

    private void Report(IntegrityCycleStats s, long allocatedBytes) =>
        output.WriteLine($"{(s.Full ? "Full" : "Incremental")} check: {s.Total.TotalSeconds:N1} s "
                         + $"(chain {s.EntriesHashed:N0} entries in {s.Chain.TotalSeconds:N1} s; "
                         + $"records {s.RecordsChecked:N0} in {s.Records.TotalSeconds:N1} s, "
                         + $"{s.RecordsChecked / Math.Max(0.001, s.Records.TotalSeconds):N0}/s); "
                         + $"{allocatedBytes / 1_048_576.0:N0} MB allocated.");

    // Records written outside the interceptor, each with a create and two update entries chained as CaseBook writes them.
    private async Task SeedAsync(TestDatabase database, int count)
    {
        await using var db = new AppDbContext(database.OptionsWithoutInterceptors);
        db.ChangeTracker.AutoDetectChangesEnabled = false;
        var caseId = await db.Cases.Select(c => c.Id).FirstAsync();
        var head = await db.AuditLog.AsNoTracking().OrderByDescending(a => a.Sequence).FirstAsync();
        const int batch = 2_000;
        for (var done = 0; done < count; done += batch)
        {
            var notes = new List<AnalystNote>();
            var steps = new List<TimelineEntry>();
            var entries = new List<AuditLogEntry>();
            for (var i = done; i < Math.Min(count, done + batch); i++)
            {
                var at = _clock.UtcNow.AddMinutes(-count + i);
                IHashableEntity row;
                string type, text;
                if (i % 2 == 0)
                {
                    var note = new AnalystNote
                    {
                        CaseId = caseId, CreatedBy = "alice", CreatedAtUtc = at,
                        Body = $"Observed beaconing from host WS-{i:D6} to 203.0.113.{i % 250}; isolated it and pulled the EDR timeline for review.",
                    };
                    notes.Add(note);
                    (row, type, text) = (note, nameof(AnalystNote), note.Body);
                }
                else
                {
                    var step = new TimelineEntry
                    {
                        CaseId = caseId, CreatedBy = "alice", CreatedAtUtc = at, OccurredAtUtc = at,
                        Kind = i % 4 == 1 ? TimelineKind.Event : TimelineKind.Investigation,
                        Description = $"Credential dumping on WS-{i:D6}: lsass memory read by an unsigned binary from a user temp folder.",
                        Source = "EDR",
                    };
                    if (step.Kind == TimelineKind.Event) step.Tactics.Add(new EventStepTactic { TimelineEntryId = step.Id, Tactic = MitreTactic.CredentialAccess });
                    steps.Add(step);
                    (row, type, text) = (step, nameof(TimelineEntry), step.Description);
                }
                row.RowHash = _hasher.ComputeRowHash(row);
                var id = ((Entity)row).Id;
                var created = new Dictionary<string, object?>
                {
                    ["Id"] = id, ["CaseId"] = caseId, ["Text"] = "draft", ["CreatedBy"] = "alice", ["CreatedAtUtc"] = at, ["RowHash"] = "draft",
                };
                var edited = new Dictionary<string, object?> { ["Text"] = text[..20], ["RowHash"] = "edited" };
                var final = new Dictionary<string, object?> { ["Text"] = text, ["RowHash"] = row.RowHash };
                foreach (var (action, after) in new[] { (AuditAction.Create, created), (AuditAction.Update, edited), (AuditAction.Update, final) })
                {
                    var entry = new AuditLogEntry
                    {
                        AtUtc = at, Actor = "alice", Action = action, EntityType = type, EntityId = id.ToString(),
                        AfterJson = JsonSerializer.Serialize(after),
                    };
                    _hasher.ChainAppend(entry, head);
                    head = entry;
                    entries.Add(entry);
                }
            }
            db.Notes.AddRange(notes);
            db.TimelineEntries.AddRange(steps);
            db.AuditLog.AddRange(entries);
            await db.SaveChangesAsync();
            db.ChangeTracker.Clear();
        }
    }

    private sealed class NoAlerts : IIntegrityAlertNotifier
    {
        public Task OnChainBrokenAsync(ChainVerificationResult result, CancellationToken ct = default) => Task.CompletedTask;
    }
}
