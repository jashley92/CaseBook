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
    public async Task A_long_file_name_is_recorded_within_the_target_label_column(/* C12 */)
    {
        // The sanitiser's 512 characters plus its ellipsis didn't fit the 500-character column: on SQL Server the access
        // row was refused, and the failure only logged.
        NewContext();
        var caseId = SeedCase();
        await NewService().RecordArtifactAsync(AccessType.EvidenceDownload, caseId, new string('f', 700) + ".pdf");

        using var db = NewContext();
        var row = await db.CaseAccessEvents.AsNoTracking().SingleAsync();
        row.TargetLabel.Should().EndWith("…");
        GeneratedTextFitsColumnTests.AssertFits(db, row);
    }

    [Fact]
    public async Task A_case_restricted_since_the_last_open_starts_a_new_row(/* BUG-289 */)
    {
        NewContext();
        var caseId = SeedCase();
        var svc = NewService();

        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: false);
        _clock.UtcNow = _clock.UtcNow.AddMinutes(10);
        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: true);

        using var db = NewContext();
        (await db.CaseAccessEvents.AsNoTracking().ToListAsync()).Select(r => r.WasRestricted).Should().BeEquivalentTo([false, true]);
    }

    [Fact]
    public async Task Each_export_is_its_own_row_with_its_own_file_name(/* BUG-154 */)
    {
        NewContext();
        var svc = NewService();

        await svc.RecordArtifactAsync(AccessType.Export, null, "incident-metrics-20261012-1000.csv");
        _clock.UtcNow = _clock.UtcNow.AddMinutes(10);
        await svc.RecordArtifactAsync(AccessType.Export, null, "access-log.csv (start to now, actor jdoe)");
        _clock.UtcNow = _clock.UtcNow.AddMinutes(5);
        await svc.RecordArtifactAsync(AccessType.Export, null, "compliance-bundle-2026-Q3.zip");

        using var db = NewContext();
        (await db.CaseAccessEvents.AsNoTracking().OrderBy(e => e.FirstSeenUtc).Select(e => e.TargetLabel).ToListAsync())
            .Should().Equal("incident-metrics-20261012-1000.csv", "access-log.csv (start to now, actor jdoe)", "compliance-bundle-2026-Q3.zip");
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
    public async Task A_session_that_began_in_the_range_and_ran_past_it_is_in_the_range(/* WF-44 */)
    {
        NewContext();
        var caseId = SeedCase();
        var svc = NewService();
        var start = _clock.UtcNow;   // Monday noon
        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: false);
        for (var i = 0; i < 60; i++)   // left open and reloaded every 20 minutes, into Tuesday
        {
            _clock.UtcNow = _clock.UtcNow.AddMinutes(20);
            await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: false);
        }

        _user.RoleSet = [AppRole.SysAdmin];
        var day = new DateTimeOffset(start.UtcDateTime.Date, TimeSpan.Zero);
        var monday = await svc.QueryAsync(new AccessLogFilter { FromUtc = day, ToUtc = day.AddDays(1).AddTicks(-1) });
        monday.Should().ContainSingle().Which.FirstSeenUtc.Should().Be(start);
        (await svc.QueryAsync(new AccessLogFilter { FromUtc = start.AddDays(3) })).Should().BeEmpty();
        (await svc.QueryAsync(new AccessLogFilter { ToUtc = start.AddMinutes(-1) })).Should().BeEmpty();
    }

    [Fact]
    public async Task A_to_date_of_the_last_calendar_day_queries_without_error(/* BUG-463 */)
    {
        NewContext();
        var caseId = SeedCase();
        var svc = NewService();
        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: false);

        // The page's end-of-day bound for a "To" of 9999-12-31, which AddDays(1) couldn't build.
        var lastDay = DateOnly.MaxValue.ToDateTime(TimeOnly.MinValue);
        var toUtc = new DateTimeOffset(DateOnly.FromDateTime(lastDay).ToDateTime(TimeOnly.MaxValue), TimeSpan.Zero);
        toUtc.Should().Be(DateTimeOffset.MaxValue);
        _user.RoleSet = [AppRole.SysAdmin];
        (await svc.QueryAsync(new AccessLogFilter { ToUtc = toUtc })).Should().ContainSingle();
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

        _user.RoleSet = [AppRole.SysAdmin];   // reading the access log is an administrator's
        var mine = await svc.QueryAsync(new AccessLogFilter { Actor = "analyst1" });
        mine.Should().ContainSingle().Which.ActorUserId.Should().Be("analyst1");

        var opens = await svc.QueryAsync(new AccessLogFilter { AccessType = AccessType.CaseOpen });
        opens.Should().HaveCount(2);
    }

    [Fact]
    public async Task Only_an_administrator_can_query_the_access_log_or_list_its_actors()
    {
        // The page and the CSV export require Administer; the service asserts it too, for any other caller.
        NewContext();
        var caseId = SeedCase();
        var svc = NewService();
        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: false);

        _user.RoleSet = [AppRole.Manager];   // ViewAllCases, but not Administer
        await svc.Invoking(s => s.QueryAsync(new AccessLogFilter())).Should().ThrowAsync<ForbiddenException>();
        await svc.Invoking(s => s.ActorsAsync()).Should().ThrowAsync<ForbiddenException>();
        _siem.Events.Should().Contain(e => e.EventId == SecurityEventIds.ActionRefused
                                           && e.Detail!.Contains("IAccessLogService.QueryAsync"));

        _user.RoleSet = [AppRole.SysAdmin];
        (await svc.QueryAsync(new AccessLogFilter())).Should().ContainSingle();
        (await svc.ActorsAsync()).Should().Equal("analyst1");
    }

    [Fact]
    public async Task A_reload_of_a_case_already_open_sends_no_new_open_to_the_siem(/* BUG-243 */)
    {
        NewContext();
        var caseId = SeedCase(restricted: true);
        var svc = NewService();
        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: true);
        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: true, stillOpen: true);
        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: true, stillOpen: true);
        _siem.Events.Count(e => e.EventId is SecurityEventIds.CaseOpened or SecurityEventIds.RestrictedCaseAccessed).Should().Be(1);
    }

    [Fact]
    public async Task The_same_open_built_twice_in_moments_is_one_open(/* REV-21 */)
    {
        NewContext();
        var caseId = SeedCase(restricted: true);
        var svc = NewService();
        await svc.RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: true);   // the prerender
        _clock.UtcNow = _clock.UtcNow.AddSeconds(2);
        await NewService().RecordCaseOpenAsync(caseId, "2026-01_Alpha", wasRestricted: true);   // the live page, a fresh component

        _siem.Events.Count(e => e.EventId == SecurityEventIds.RestrictedCaseAccessed).Should().Be(1);
        _user.RoleSet = [AppRole.SysAdmin];
        (await svc.QueryAsync(new AccessLogFilter { AccessType = AccessType.CaseOpen })).Should().ContainSingle()
            .Which.Count.Should().Be(1);
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
