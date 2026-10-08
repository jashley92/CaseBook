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

    // The Program overview's Needs action list: notices first, then what fell due earliest; clocks for every running notice.
    [Fact]
    public async Task Needs_action_lists_notices_targets_briefs_tasks_and_actions_with_notices_first()
    {
        var now = _clock.UtcNow;
        var atRisk = NewMaterialBreach(MaterialityStatus.Material, now.AddHours(-60));      // 60 of 72 h: at risk
        var onTrack = NewMaterialBreach(MaterialityStatus.Material, now.AddHours(-2));      // a clock, not an item
        var late = Case.Open(2026, 50, "Late", "Not contained", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "a", now.AddDays(-3));
        late.DetectedAtUtc = now.AddHours(-30);                                              // past a 12 h target
        late.ActionItems.Add(new ActionItem { CaseId = late.Id, Title = "Collect logs", DueAtUtc = now.AddDays(-1),
            CreatedBy = "a", CreatedAtUtc = now.AddDays(-2) });
        await SeedAsync(atRisk, onTrack, late);
        await using (var db = NewContext())
        {
            db.CaseBriefs.Add(new CaseBrief { CaseId = late.Id, Summary = "s", CreatedBy = "a", CreatedAtUtc = now.AddDays(-2) });
            db.TimelineEntries.Add(new TimelineEntry { CaseId = late.Id, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Decision,
                OccurredAtUtc = now.AddHours(-5), Description = "Isolate the host", CreatedBy = "a", CreatedAtUtc = now.AddHours(-5) });
            db.ImprovementActions.Add(new ImprovementAction { CaseId = late.Id, Title = "MFA", CreatedBy = "a",
                CreatedAtUtc = now.AddDays(-20), TargetDateUtc = now.AddDays(-4) });
            await db.SaveChangesAsync();
        }
        _settings.Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 72, 80);
        var targets = new IncidentManager.Application.Sla.SlaTargets(new Dictionary<(IncidentManager.Application.Sla.SlaClock, Severity), int>
        {
            [(IncidentManager.Application.Sla.SlaClock.Containment, Severity.High)] = 12
        }, 80);
        var f = NewFactory();

        var na = await new NeedsActionService(f, _user, _clock, new TestSlaTargets(targets), _settings,
            new NotificationRuleService(f, _user, _clock)).GetAsync();

        // The two breaches (detected 10 days ago) are long past the 12 h containment target too, so they come first
        // after the notice; then the action 4 days over, the task 1 day over, the late case 18 h over, and the brief.
        na.Items.Select(i => i.Kind).Should().Equal(NeedsActionKind.Notify, NeedsActionKind.Sla, NeedsActionKind.Sla,
            NeedsActionKind.Actions, NeedsActionKind.Tasks, NeedsActionKind.Sla, NeedsActionKind.Brief);
        na.Items[0].Should().Match<NeedsActionItem>(i => i.CaseId == atRisk.Id && !i.Over && i.What == "Notify New York: 72 h window");
        na.Items.Single(i => i.Kind == NeedsActionKind.Sla && i.CaseId == late.Id).What.Should().Be("Not contained within its 12 h target");
        na.Items.Single(i => i.Kind == NeedsActionKind.Brief).What.Should().Be("Brief v1 predates a decision");
        na.Clocks.Select(c => c.CaseId).Should().Equal(atRisk.Id, onTrack.Id);
    }

    // Where open cases are: severity within each phase, and how long the longest-waiting one has been in it.
    [Fact]
    public async Task Phase_aging_counts_severity_and_the_longest_time_in_each_phase()
    {
        var now = _clock.UtcNow;
        Case Open(int seq, Severity sev, DateTimeOffset opened) => Case.Open(2026, 100 + seq, $"P{seq}", $"P{seq}",
            Classification.Incident, sev, CaseOrigin.InternalDetection, "a", opened);
        var a = Open(1, Severity.High, now.AddDays(-5));
        a.ChangePhase(CasePhase.Triage, "looking", "a", now.AddDays(-3));
        var b = Open(2, Severity.Low, now.AddDays(-2));
        b.ChangePhase(CasePhase.Triage, "looking", "a", now.AddDays(-1));
        var fresh = Open(3, Severity.Medium, now.AddHours(-6));
        await SeedAsync(a, b, fresh);

        var phases = await NewDashboard().PhaseAgingAsync();

        var triage = phases.Single(p => p.Phase == CasePhase.Triage);
        triage.Count.Should().Be(2);
        triage.BySeverity.Where(x => x.Count > 0).Should().Equal(new CountBy<Severity>(Severity.High, 1), new CountBy<Severity>(Severity.Low, 1));
        triage.LongestInPhase.Should().Be(TimeSpan.FromDays(3));
        phases.Single(p => p.Phase == CasePhase.New).LongestInPhase.Should().Be(TimeSpan.FromHours(6), "no change yet: since it was opened");
        phases.Should().NotContain(p => p.Phase == CasePhase.Closed);
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
