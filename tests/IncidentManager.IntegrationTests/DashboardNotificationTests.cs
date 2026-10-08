using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Dashboards;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>PROD-07 follow-up: the leadership dashboard's notification-deadline aggregates.</summary>
public sealed class DashboardNotificationTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 16, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "mgr", RoleSet = [AppRole.Manager] };
    private readonly StubSettings _settings = new();

    public DashboardNotificationTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = NewContext();
    }

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private DashboardService NewDashboard() =>
        new(NewFactory(), _user, _clock, new TestSlaTargets(), _settings,
            new NotificationRuleService(NewFactory(), _user, _clock));

    private int _seq;

    private Case NewMaterialBreach(MaterialityStatus mat, DateTimeOffset decidedOn, DateTimeOffset? reportedAt = null)
    {
        var seq = ++_seq;
        var c = Case.Open(2026, seq, $"Breach{seq}", $"Breach {seq}", Classification.Breach, Severity.High,
            CaseOrigin.InternalDetection, "a", _clock.UtcNow.AddDays(-10));
        c.SetImpactAssessment(500, new[] { "SSN" }, "NY", "a", _clock.UtcNow);
        if (mat == MaterialityStatus.Material)
            c.RecordMateriality(MaterialityStatus.Material, "Committee", decidedOn, "harm", "a", _clock.UtcNow);
        if (reportedAt is { } r) c.MarkReported(r, "a", _clock.UtcNow);
        return c;
    }

    private async Task SeedAsync(params Case[] cases)
    {
        await using var db = NewContext();
        db.DataElements.Add(new DataElement { Key = "SSN", Label = "SSN", NotificationJurisdictions = "NY",
            IsActive = true, IsSystem = false, CreatedBy = "s", CreatedAtUtc = _clock.UtcNow });
        db.NotificationRules.Add(new NotificationRule { Code = "NY", Label = "New York", WindowHours = 72,
            IsActive = true, IsSystem = true, CreatedBy = "s", CreatedAtUtc = _clock.UtcNow });
        db.Cases.AddRange(cases);
        await db.SaveChangesAsync();
    }

    // The Program overview's "Regulatory notice" row: notices made in the window, inside or outside their window.
    [Fact]
    public async Task Notices_made_in_a_window_count_as_inside_or_outside_their_jurisdiction_window()
    {
        var now = _clock.UtcNow;
        await SeedAsync(
            NewMaterialBreach(MaterialityStatus.Material, now.AddHours(-100), reportedAt: now.AddHours(-90)),   // 10 h: inside 72 h
            NewMaterialBreach(MaterialityStatus.Material, now.AddHours(-100), reportedAt: now.AddHours(-10)),   // 90 h: outside
            NewMaterialBreach(MaterialityStatus.Material, now.AddHours(-1)));                                    // not reported yet
        _settings.Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 72, 80);
        var f = NewFactory();
        var program = new ProgramReportService(f, _user, _clock, new TestSlaTargets(),
            new IncidentManager.Application.Mitre.AttackCoverageService(f, _user, _clock), null, _settings,
            new NotificationRuleService(f, _user, _clock));

        var snaps = await program.SnapshotsAsync([new ProgramWindow(now.AddDays(-30), now, "30 days"),
            new ProgramWindow(now.AddHours(-50), now, "the last 50 hours")]);

        (snaps[0].NoticesMet, snaps[0].NoticesMissed, snaps[0].NoticesPercent).Should().Be((1, 1, 50));
        (snaps[1].NoticesMet, snaps[1].NoticesMissed).Should().Be((0, 1), "only the late notice was made in the last 50 hours");
    }

    [Fact]
    public async Task When_the_feature_is_off_the_dashboard_reports_no_notification_metrics()
    {
        await SeedAsync(NewMaterialBreach(MaterialityStatus.Material, _clock.UtcNow.AddHours(-1)));
        _settings.Current = NotificationDeadlineSettings.Off;

        var m = await NewDashboard().GetAsync();
        m.NotifyDeadlinesEnabled.Should().BeFalse();
        m.NotifyAwaitingReport.Should().Be(0);
    }

    [Fact]
    public async Task Open_material_breaches_are_counted_at_risk_or_breached_by_their_deadline()
    {
        await SeedAsync(
            NewMaterialBreach(MaterialityStatus.Material, _clock.UtcNow.AddHours(-1)),   // ~1h in → on track
            NewMaterialBreach(MaterialityStatus.Material, _clock.UtcNow.AddHours(-80)),  // past 72h → breached
            NewMaterialBreach(MaterialityStatus.UnderReview, _clock.UtcNow.AddHours(-80))); // no material call → not counted
        _settings.Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 72, 80);

        var m = await NewDashboard().GetAsync();
        m.NotifyDeadlinesEnabled.Should().BeTrue();
        m.NotifyAwaitingReport.Should().Be(2);   // the two Material ones with a running clock
        m.NotifyBreached.Should().Be(1);
        m.NotifyAtRisk.Should().Be(0);
    }

    [Fact]
    public async Task A_reported_case_leaves_the_queue_and_feeds_the_detected_to_reported_mean()
    {
        var detected = _clock.UtcNow.AddDays(-10);
        var reported = detected.AddHours(48);
        var c = NewMaterialBreach(MaterialityStatus.Material, detected.AddHours(1), reportedAt: reported);
        await SeedAsync(c);
        _settings.Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 72, 80);

        var m = await NewDashboard().GetAsync();
        m.NotifyAwaitingReport.Should().Be(0, "the case has been reported");
        m.MeanHoursToReport.Should().BeApproximately(48, 0.5);
    }

    [Fact]
    public async Task A_closed_case_with_an_unrecorded_notification_stays_counted()
    {
        // INV-43: closing a case doesn't answer its notification; the dashboard keeps counting it until reported.
        var closed = NewMaterialBreach(MaterialityStatus.Material, _clock.UtcNow.AddHours(-80));
        closed.ChangePhase(CasePhase.Closed, "Done", "mgr", _clock.UtcNow);
        var closedReported = NewMaterialBreach(MaterialityStatus.Material, _clock.UtcNow.AddHours(-80), reportedAt: _clock.UtcNow.AddHours(-10));
        closedReported.ChangePhase(CasePhase.Closed, "Done", "mgr", _clock.UtcNow);
        await SeedAsync(closed, closedReported);
        _settings.Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 72, 80);

        var m = await NewDashboard().GetAsync();
        m.NotifyAwaitingReport.Should().Be(1);
        m.NotifyBreached.Should().Be(1);
    }

    [Fact]
    public async Task The_case_list_notification_filter_lists_the_cases_the_dashboard_counts()
    {
        var onTrack = NewMaterialBreach(MaterialityStatus.Material, _clock.UtcNow.AddHours(-1));
        var overdue = NewMaterialBreach(MaterialityStatus.Material, _clock.UtcNow.AddHours(-80));
        var undecided = NewMaterialBreach(MaterialityStatus.UnderReview, _clock.UtcNow.AddHours(-80));
        await SeedAsync(onTrack, overdue, undecided);
        var cases = new CaseService(NewFactory(), _user, _clock, new CaseNumberGenerator(NewContext()),
            new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(),
            new TestSlaTargets(), notifySettings: _settings, notifyRules: new NotificationRuleService(NewFactory(), _user, _clock));

        _settings.Current = NotificationDeadlineSettings.Off;
        (await cases.ListAsync(new CaseFilter { NotifyDeadlineOnly = true })).Items.Should().BeEmpty("the feature is off");

        _settings.Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 72, 80);
        var page = await cases.ListAsync(new CaseFilter { NotifyDeadlineOnly = true });
        page.Items.Should().ContainSingle().Which.Id.Should().Be(overdue.Id);
        (await NewDashboard().GetAsync()).NotifyBreached.Should().Be(page.Total);
    }


    private sealed class StubSettings : INotificationDeadlineSettingsProvider
    {
        public NotificationDeadlineSettings Current { get; set; } = NotificationDeadlineSettings.Off;
    }

    public void Dispose() => _connection.Dispose();
}
