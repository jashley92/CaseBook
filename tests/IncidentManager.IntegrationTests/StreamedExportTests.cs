using System.Diagnostics;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Access;
using IncidentManager.Application.Common;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Access;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Xunit.Abstractions;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-32: the audit and access-log CSVs are streamed as they're read instead of built in memory and silently cut at
/// 100,000 rows. For a small set the file is byte for byte what the in-memory build gives (a byte-order mark and the same
/// text); a cut says so at the top and the end; the access is recorded before the first byte; the access log stays an
/// administrator's. A large set (past the old bound) completes; <c>CASEBOOK_THROUGHPUT_ROWS</c> sets its size. Runs on
/// SQLite and, when a server is configured, on SQL Server.
/// </summary>
public sealed class StreamedExportTests(ITestOutputHelper output) : IDisposable
{
    private TestDatabase? _db;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 17, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _admin = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };

    private void Open(string provider) =>
        _db = TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _admin, _clock, new CaseChangeNotifier()));

    private IntegrityService Integrity(TestCurrentUser user) =>
        new(new TestDbContextFactory(_db!.OptionsWithoutInterceptors), _hasher, null!, null!, user, _clock,
            new IntegrityMonitor(), new NoOpIntegrityAlerts());

    private AccessLogService AccessLog(TestCurrentUser user) =>
        new(_db!.Factory(), new Policy(), user, _clock, new CapturingSecurityEventSink(), NullLogger<AccessLogService>.Instance);

    private sealed class NoOpIntegrityAlerts : IIntegrityAlertNotifier
    {
        public Task OnChainBrokenAsync(ChainVerificationResult result, CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed class Policy : IAccessLogPolicy
    {
        public AccessLogScope Scope => AccessLogScope.All;
        public TimeSpan CoalesceWindow => TimeSpan.FromMinutes(30);
        public bool ShouldLog(AccessType type, bool wasRestricted) => true;
    }

    private static byte[] Excel(string csv) => [.. Encoding.UTF8.GetPreamble(), .. Encoding.UTF8.GetBytes(csv)];

    private async Task SeedTrailAsync()
    {
        await using var db = _db!.NewContext();
        var c = Case.Open(2026, 1, "Streamed", "Streamed export", Classification.Incident, Severity.Medium,
            CaseOrigin.InternalDetection, "admin1", _clock.UtcNow);
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        for (var i = 0; i < 6; i++)
        {
            _clock.UtcNow = _clock.UtcNow.AddMinutes(1);
            c.AddEventStep(_clock.UtcNow, [MitreTactic.Discovery], null, null, null, $"Step {i}, with \"quotes\"; =1+1", null, "admin1", _clock.UtcNow);
            await db.SaveChangesAsync();
        }
    }

    private CaseAccessEvent Access(int i, string actor = "alice") => new()
    {
        ActorUserId = actor, CaseNumber = "2026-0001", AccessType = AccessType.CaseOpen, TargetLabel = $"open {i}, =cmd",
        FirstSeenUtc = _clock.UtcNow.AddMinutes(-10 - i), LastSeenUtc = _clock.UtcNow.AddMinutes(-i), Count = i + 1,
    };

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_streamed_audit_csv_is_the_file_the_old_export_built(string provider)
    {
        Open(provider);
        await SeedTrailAsync();
        var svc = Integrity(_admin);
        var filter = new AuditQueryFilter();

        foreach (var limit in new[] { 1_000_000, 3 })
        {
            var all = await svc.QueryAsync(filter, limit + 1);
            var cut = all.Count > limit;
            var old = Excel(AuditCsv.Build(all.Take(limit).ToList(), _clock.UtcNow, null, cut ? limit : null));

            using var ms = new MemoryStream();
            long? bytesAtStart = null;
            (int Rows, bool Cut)? told = null;
            var result = await svc.WriteCsvAsync(filter, ms, limit, (rows, truncated) =>
            {
                (bytesAtStart, told) = (ms.Length, (rows, truncated));
                return Task.CompletedTask;
            }, null);

            ms.ToArray().Should().Equal(old, $"limit {limit}: the same bytes as the in-memory build");
            result.Should().Be(new CsvStreamResult(Math.Min(all.Count, limit), cut, TimedOut: false));
            told.Should().Be((Math.Min(all.Count, limit), cut));
            bytesAtStart.Should().Be(0, "the access is recorded before the first byte");
        }
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_streamed_audit_csv_keeps_need_to_know(string provider)
    {
        Open(provider);
        await SeedTrailAsync();
        await using (var db = _db!.NewContext())
        {
            var c = await db.Cases.SingleAsync();
            c.IsRestricted = true;
            c.IncidentCommander = "commander1";
            await db.SaveChangesAsync();
        }
        var outsider = new TestCurrentUser { UserId = "analyst9", RoleSet = [AppRole.Analyst] };
        var export = await Integrity(outsider).ExportCsvAsync(new AuditQueryFilter(), 1_000_000);
        export.Rows.Should().Be(0);
        export.Csv.Should().NotContain("Streamed export").And.NotContain("Step 0");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_streamed_access_log_csv_is_the_file_the_old_export_built_and_says_a_cut_at_both_ends(string provider)
    {
        Open(provider);
        await using (var db = _db!.NewContext())
        {
            db.CaseAccessEvents.AddRange(Enumerable.Range(0, 6).Select(i => Access(i, i % 2 == 0 ? "alice" : "bob")));
            await db.SaveChangesAsync();
        }
        var svc = AccessLog(_admin);
        var filter = new AccessLogFilter();

        foreach (var limit in new[] { 1_000_000, 2 })
        {
            var all = await svc.QueryAsync(filter, limit + 1);
            var cut = all.Count > limit;
            var old = Excel(AccessLogCsv.Build(all.Take(limit).ToList(), _clock.UtcNow, cut ? limit : null));

            using var ms = new MemoryStream();
            var result = await svc.WriteCsvAsync(filter, ms, limit, null, null);
            ms.ToArray().Should().Equal(old, $"limit {limit}");
            result.Truncated.Should().Be(cut);
            if (cut)
            {
                var lines = Encoding.UTF8.GetString(ms.ToArray()).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                lines[1].Should().StartWith("# Truncated: only the newest 2 rows");
                lines[^1].Should().Be("# Truncated at 2 rows: narrow the range to export the rest.");
            }
        }

        using var bobs = new MemoryStream();
        (await svc.WriteCsvAsync(new AccessLogFilter { Actor = "bob" }, bobs, 100, null, null)).Rows.Should().Be(3);

        var analyst = new TestCurrentUser { UserId = "analyst1", RoleSet = [AppRole.Analyst] };
        var act = () => AccessLog(analyst).WriteCsvAsync(filter, new MemoryStream(), 100, null, null);
        await act.Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>("who read what is an administrator's");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_large_access_log_streams_past_the_old_bound_in_full(string provider /* throughput */)
    {
        var rows = int.TryParse(Environment.GetEnvironmentVariable("CASEBOOK_THROUGHPUT_ROWS"), out var n) && n > 0 ? n : 100_500;
        Open(provider);
        var seed = Stopwatch.StartNew();
        for (var start = 0; start < rows; start += 10_000)
        {
            await using var db = _db!.NewContext();
            db.ChangeTracker.AutoDetectChangesEnabled = false;
            db.CaseAccessEvents.AddRange(Enumerable.Range(start, Math.Min(10_000, rows - start)).Select(i => Access(i % 50_000)));
            await db.SaveChangesAsync();
        }
        output.WriteLine($"{provider}: seeded {rows:N0} sessions in {seed.Elapsed.TotalSeconds:N1} s.");

        var run = Stopwatch.StartNew();
        var file = Path.GetTempFileName();
        try
        {
            CsvStreamResult result;
            await using (var fs = new FileStream(file, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16, useAsync: true))
                result = await AccessLog(_admin).WriteCsvAsync(new AccessLogFilter(), fs, CsvStream.MaxRows, null, null);
            output.WriteLine($"{provider}: streamed {result.Rows:N0} rows ({new FileInfo(file).Length / 1048576d:N1} MB) in {run.Elapsed.TotalSeconds:N1} s.");

            result.Should().Be(new CsvStreamResult(rows, Truncated: false, TimedOut: false));
            var lines = 0;
            using (var reader = new StreamReader(file)) while (await reader.ReadLineAsync() is not null) lines++;
            lines.Should().Be(rows + 2, "the comment, the header and every row: nothing silently cut");
        }
        finally { File.Delete(file); }
    }

    public void Dispose() => _db?.Dispose();
}
