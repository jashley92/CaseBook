using FluentAssertions;
using IncidentManager.Application.Access;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Access;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

public sealed class AccessLogPersistenceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 24, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();
    private readonly TestAccessLogPolicy _policy = new();
    private readonly CapturingSecurityEventSink _siem = new();

    public AccessLogPersistenceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    private TestDbContextFactory NewFactory() =>
        new(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private AccessLogService NewService() =>
        new(NewFactory(), _policy, _user, _clock, _siem, NullLogger<AccessLogService>.Instance);

    private int _seq;

    private Guid SeedCase(bool restricted = false)
    {
        using var db = NewContext();
        var seq = ++_seq; // distinct sequence per seed so the unique IRP index isn't tripped
        var c = Case.Open(2026, seq, $"Case{seq}", $"Case {seq}", Classification.Incident, Severity.Medium,
            CaseOrigin.InternalDetection, "sys", _clock.UtcNow);
        c.IsRestricted = restricted;
        db.Cases.Add(c);
        db.SaveChanges();
        return c.Id;
    }

    [Fact]
    public async Task Two_opens_within_the_window_coalesce_into_one_session()
    {
        NewContext(); // ensure schema
        var caseId = SeedCase();
        var svc = NewService();

        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: false);
        _clock.UtcNow = _clock.UtcNow.AddMinutes(10);
        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: false);

        using var db = NewContext();
        var rows = await db.CaseAccessEvents.AsNoTracking().ToListAsync();
        rows.Should().HaveCount(1);
        rows[0].Count.Should().Be(2);
        rows[0].AccessType.Should().Be(AccessType.CaseOpen);
    }

    [Fact]
    public async Task Opens_outside_the_window_start_a_second_session()
    {
        NewContext();
        var caseId = SeedCase();
        var svc = NewService();

        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: false);
        _clock.UtcNow = _clock.UtcNow.AddMinutes(31); // past the 30-minute window
        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: false);

        using var db = NewContext();
        (await db.CaseAccessEvents.CountAsync()).Should().Be(2);
    }

    [Fact]
    public async Task RestrictedOnly_scope_skips_a_normal_open_but_records_a_restricted_open_and_a_download()
    {
        NewContext();
        _policy.Scope = AccessLogScope.RestrictedOnly;
        var normal = SeedCase(restricted: false);
        var secret = SeedCase(restricted: true);
        var svc = NewService();

        await svc.RecordCaseOpenAsync(normal, "2026-01_Alpha", wasRestricted: false); // skipped
        await svc.RecordCaseOpenAsync(secret, "2026-01_Alpha", wasRestricted: true);  // kept
        await svc.RecordArtifactAsync(AccessType.EvidenceDownload, normal, "evidence.bin", Guid.NewGuid()); // kept

        using var db = NewContext();
        var rows = await db.CaseAccessEvents.AsNoTracking().ToListAsync();
        rows.Should().HaveCount(2);
        rows.Should().ContainSingle(e => e.AccessType == AccessType.CaseOpen && e.WasRestricted);
        rows.Should().ContainSingle(e => e.AccessType == AccessType.EvidenceDownload);
        rows.Should().NotContain(e => e.AccessType == AccessType.CaseOpen && !e.WasRestricted);
    }

    [Fact]
    public async Task Off_scope_records_nothing()
    {
        NewContext();
        _policy.Scope = AccessLogScope.Off;
        var caseId = SeedCase(restricted: true);
        var svc = NewService();

        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: true);
        await svc.RecordArtifactAsync(AccessType.Export, null, "metrics.csv");

        using var db = NewContext();
        (await db.CaseAccessEvents.CountAsync()).Should().Be(0);
    }

    [Fact]
    public async Task An_artifact_download_resolves_the_case_number_and_restricted_flag()
    {
        NewContext();
        var caseId = SeedCase(restricted: true);
        var svc = NewService();

        await svc.RecordArtifactAsync(AccessType.EvidenceDownload, caseId, "evidence.bin", Guid.NewGuid());

        using var db = NewContext();
        var row = await db.CaseAccessEvents.AsNoTracking().SingleAsync();
        row.CaseNumber.Should().Be("2026-01_Case1"); // resolved from the seeded case, not the passed label
        row.WasRestricted.Should().BeTrue();
        row.TargetLabel.Should().Be("evidence.bin");
    }

    [Fact]
    public async Task Access_logging_leaves_the_hash_chain_untouched_and_valid()
    {
        NewContext();
        var caseId = SeedCase(); // produces audit-chain entries
        long chainCountBefore;
        using (var db = NewContext())
            chainCountBefore = await db.AuditLog.CountAsync();

        var svc = NewService();
        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: false);
        await svc.RecordArtifactAsync(AccessType.Export, null, "metrics.csv");

        using (var db = NewContext())
        {
            // No new audit-chain rows, and none describing the access-log entity.
            (await db.AuditLog.CountAsync()).Should().Be((int)chainCountBefore);
            (await db.AuditLog.AnyAsync(a => a.EntityType == nameof(CaseAccessEvent))).Should().BeFalse();

            var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
            _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        }
    }

    [Fact]
    public async Task Query_filters_by_actor_and_access_type()
    {
        NewContext();
        var caseId = SeedCase();
        var svc = NewService();

        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: false);
        _user.UserId = "analyst2";
        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: false);

        var mine = await svc.QueryAsync(new AccessLogFilter { Actor = "analyst1" });
        mine.Should().ContainSingle().Which.ActorUserId.Should().Be("analyst1");

        var opens = await svc.QueryAsync(new AccessLogFilter { AccessType = AccessType.CaseOpen });
        opens.Should().HaveCount(2);
    }

    [Fact]
    public async Task Access_emits_the_matching_security_event_to_the_siem_stream()
    {
        NewContext();
        var normal = SeedCase(restricted: false);
        var secret = SeedCase(restricted: true);
        var svc = NewService();

        await svc.RecordCaseOpenAsync(normal, "2026-01_Case1", wasRestricted: false);
        await svc.RecordCaseOpenAsync(secret, "2026-02_Case2", wasRestricted: true);
        await svc.RecordArtifactAsync(AccessType.EvidenceDownload, normal, "evidence.bin", Guid.NewGuid());

        _siem.Events.Should().Contain(e => e.EventId == SecurityEventIds.CaseOpened);           // 5301
        _siem.Events.Should().Contain(e => e.EventId == SecurityEventIds.RestrictedCaseAccessed); // 5305
        _siem.Events.Should().Contain(e => e.EventId == SecurityEventIds.EvidenceDownloaded);    // 5302
    }

    [Fact]
    public async Task Siem_emission_is_independent_of_the_access_log_scope()
    {
        NewContext();
        _policy.Scope = AccessLogScope.Off; // C-05 store records nothing…
        var caseId = SeedCase();
        var svc = NewService();

        await svc.RecordCaseOpenAsync(caseId, "2026-01_Case1", wasRestricted: false);

        using var db = NewContext();
        (await db.CaseAccessEvents.CountAsync()).Should().Be(0);        // …store is off
        _siem.Events.Should().ContainSingle(e => e.EventId == SecurityEventIds.CaseOpened); // …but SIEM still streams
    }

    public void Dispose() => _connection.Dispose();

    private sealed class TestAccessLogPolicy : IAccessLogPolicy
    {
        public AccessLogScope Scope { get; set; } = AccessLogScope.All;
        public TimeSpan CoalesceWindow { get; set; } = TimeSpan.FromMinutes(30);
        public bool ShouldLog(AccessType type, bool wasRestricted) => AccessLogRules.ShouldLog(Scope, type, wasRestricted);
    }
}
