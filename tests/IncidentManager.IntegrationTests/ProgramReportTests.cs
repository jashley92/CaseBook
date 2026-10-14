using FluentAssertions;
using IncidentManager.Application.Dashboards;
using IncidentManager.Application.Mitre;
using IncidentManager.Application.Sla;
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

/// <summary>E-31: the quarterly program-metrics report — figures by the date things happened, vs the prior quarter.</summary>
public sealed class ProgramReportTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 24, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "mgr", RoleSet = [AppRole.Manager] };

    // Q2 2026 = Apr–Jun; Q1 = Jan–Mar.
    private static readonly ProgramPeriod Q2 = new(2026, 2);
    private static DateTimeOffset Apr(int d, int h = 0) => new(2026, 4, d, h, 0, 0, TimeSpan.Zero);
    private static DateTimeOffset Feb(int d) => new(2026, 2, d, 0, 0, 0, TimeSpan.Zero);

    public ProgramReportTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private DbContextOptions<AppDbContext> Options() =>
        new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;

    private ProgramReportService Service(SlaTargets? targets = null, TimeZoneInfo? zone = null)
    {
        var f = new TestDbContextFactory(Options());
        return new(f, _user, _clock, new TestSlaTargets(targets), new AttackCoverageService(f, _user, _clock),
            zone is null ? null : new FixedZone(zone));
    }

    private static readonly TimeZoneInfo Eastern = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");

    private sealed class FixedZone(TimeZoneInfo zone) : IncidentManager.Application.Abstractions.IOrganizationTimeZone
    {
        public TimeZoneInfo Current => zone;
    }

    private async Task SeedAsync()
    {
        await using var db = new AppDbContext(Options());
        await db.Database.EnsureCreatedAsync();

        // Q2: a High incident contained in 2h (met a 4h target), resolved in 30h, with a review + two actions.
        var a = Case.Open(2026, 1, "A", "Phish", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic", Apr(2));
        a.OccurredAtUtc = Apr(1, 18);
        a.ContainedAtUtc = Apr(2, 2);
        a.ResolvedAtUtc = Apr(3, 6);
        a.AddTechnique("T1566", "Phishing", MitreTactic.InitialAccess, "ic", Apr(2));
        // Q2: a Critical breach contained in 10h (missed a 4h target), reported, closed in Q2.
        var b = Case.Open(2026, 2, "B", "Exposure", Classification.Incident, Severity.Critical, CaseOrigin.ThirdParty, "ic", Apr(10));
        b.Reclassify(Classification.Breach, "PII in scope", "ic", Apr(11));
        b.ContainedAtUtc = Apr(10, 10);
        b.ReportedAtUtc = Apr(12);
        b.ClosedAtUtc = Apr(20);
        // Q1: one adverse event, closed in Q1.
        var c = Case.Open(2026, 3, "C", "Old", Classification.AdverseEvent, Severity.Low, CaseOrigin.InternalDetection, "ic", Feb(1));
        c.ClosedAtUtc = Feb(5);
        // A drill in Q2 — excluded by default.
        var drill = Case.Open(2026, 4, "D", "Tabletop", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic", Apr(5), isExercise: true);

        db.Cases.AddRange(a, b, c, drill);
        db.PostIncidentReviews.Add(new PostIncidentReview { CaseId = a.Id, WhatHappened = "x", CreatedAtUtc = Apr(15), CreatedBy = "ic" });
        db.ImprovementActions.AddRange(
            new ImprovementAction { CaseId = a.Id, Title = "MFA for finance", RelatedArea = "Identity", CreatedAtUtc = Apr(15), CreatedBy = "ic",
                Status = ImprovementActionStatus.Completed, ClosedAtUtc = Apr(25) },
            new ImprovementAction { CaseId = a.Id, Title = "Phish training", RelatedArea = "Awareness", CreatedAtUtc = Apr(15), CreatedBy = "ic",
                TargetDateUtc = Apr(20) });
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task Reopening_or_reclassifying_a_case_later_does_not_change_a_past_quarter(/* WF-38 */)
    {
        await using (var db = new AppDbContext(Options()))
        {
            await db.Database.EnsureCreatedAsync();
            var e = Case.Open(2026, 5, "E", "Later reopened", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "ic", Apr(3));
            e.ChangePhase(CasePhase.Closed, "Done", "ic", Apr(20), outcomeKey: "Confirmed");
            // In Q3: reopened, raised to a Breach, and closed again.
            e.Reopen("New evidence", "ic", Apr(20).AddMonths(3));
            e.Reclassify(Classification.Breach, "Data left", "ic", Apr(21).AddMonths(3));
            e.ChangePhase(CasePhase.Closed, "Done again", "ic", Apr(25).AddMonths(3), outcomeKey: "Confirmed");
            db.Cases.Add(e);
            await db.SaveChangesAsync();
        }

        var q2 = (await Service().BuildAsync(Q2)).Current;
        q2.Closed.Should().Be(1, "it was closed in Q2");
        q2.OpenAtEnd.Should().Be(0);
        q2.OpenedByClassification.Should().ContainSingle(x => x.Key == Classification.Incident, "it was an Incident at Q2's end");
    }

    [Fact]
    public async Task A_close_dated_before_the_case_was_filed_still_counts_as_closed(/* WF-97 */)
    {
        await using (var db = new AppDbContext(Options()))
        {
            await db.Database.EnsureCreatedAsync();
            // Handled before it was filed: filed on 10 Apr, detected on 1 Apr, closed "as of" 5 Apr.
            var e = Case.Open(2026, 6, "F", "Filed late", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "ic", Apr(10));
            e.DetectedAtUtc = Apr(1);
            e.ChangePhase(CasePhase.Closed, "Done", "ic", Apr(10, 1), effectiveAtUtc: Apr(5), outcomeKey: "Confirmed");
            db.Cases.Add(e);
            await db.SaveChangesAsync();
        }

        var q2 = (await Service().BuildAsync(Q2)).Current;
        q2.Closed.Should().Be(1);
        q2.OpenAtEnd.Should().Be(0, "the opening row comes before the close it was recorded before");
    }

    [Fact]
    public async Task Raising_the_severity_later_does_not_turn_a_past_met_into_missed(/* WF-76 */)
    {
        await using (var db = new AppDbContext(Options()))
        {
            await db.Database.EnsureCreatedAsync();
            var e = Case.Open(2026, 7, "G", "Contained in time", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "ic", Apr(2));
            e.DetectedAtUtc = Apr(2);
            e.ContainedAtUtc = Apr(2, 20);   // 20 h: inside Medium's 24 h, outside High's 8 h
            e.ChangeSeverity(Severity.High, "Scope grew", "ic", Apr(2).AddMonths(3));
            db.Cases.Add(e);
            await db.SaveChangesAsync();
        }
        var targets = new SlaTargets(new Dictionary<(SlaClock, Severity), int>
        {
            [(SlaClock.Containment, Severity.Medium)] = 24,
            [(SlaClock.Containment, Severity.High)] = 8,
        }, 80);

        var q2 = (await Service(targets).BuildAsync(Q2)).Current;
        q2.Sla.Should().ContainSingle(x => x.Clock == SlaClock.Containment).Which.Should().Be(new SlaAttainment(SlaClock.Containment, 1, 0));
        q2.ContainmentBySeverity.Should().ContainSingle(x => x.Severity == Severity.Medium).Which.Met.Should().Be(1);
    }

    [Fact]
    public async Task A_target_tightened_later_does_not_turn_a_past_met_into_missed(/* BUG-322 */)
    {
        var now = _clock.UtcNow;
        await using (var db = new AppDbContext(Options()))
        {
            await db.Database.EnsureCreatedAsync();
            // The Medium containment target was 24 h when the case was contained ...
            _clock.UtcNow = new DateTimeOffset(2026, 3, 1, 0, 0, 0, TimeSpan.Zero);
            var setting = new AppSetting { Key = "Sla:Containment:Medium", Value = "24", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin" };
            db.AppSettings.Add(setting);
            await db.SaveChangesAsync();
            var e = Case.Open(2026, 7, "G", "Contained in time", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "ic", Apr(2));
            e.DetectedAtUtc = Apr(2);
            e.ContainedAtUtc = Apr(2, 20);   // 20 h
            db.Cases.Add(e);
            await db.SaveChangesAsync();
            // ... and was tightened to 8 h after the quarter.
            _clock.UtcNow = new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
            setting.Value = "8";
            setting.UpdatedAtUtc = _clock.UtcNow;
            await db.SaveChangesAsync();
        }
        _clock.UtcNow = now;
        var today = new SlaTargets(new Dictionary<(SlaClock, Severity), int> { [(SlaClock.Containment, Severity.Medium)] = 8 }, 80);
        var f = new TestDbContextFactory(Options());
        var withHistory = new ProgramReportService(f, _user, _clock, new TestSlaTargets(today), new AttackCoverageService(f, _user, _clock),
            server: new NoServerValues());

        var q2 = (await withHistory.BuildAsync(Q2)).Current;

        q2.Sla.Should().ContainSingle(x => x.Clock == SlaClock.Containment).Which.Should().Be(new SlaAttainment(SlaClock.Containment, 1, 0));
        (await Service(today).BuildAsync(Q2)).Current.Sla.Single(x => x.Clock == SlaClock.Containment).Missed
            .Should().Be(1, "judged against today's target it would read as missed");
    }

    private sealed class NoServerValues : IncidentManager.Application.Abstractions.IServerSettingValues
    {
        public string? ValueOf(string key) => null;
    }

    [Fact]
    public async Task An_action_reopened_later_still_counts_as_completed_in_its_quarter(/* WF-80 */)
    {
        await SeedAsync();   // "MFA for finance" completed on 25 Apr (Q2)
        var before = (await Service().BuildAsync(Q2)).Current;
        await using (var db = new AppDbContext(Options()))
        {
            var a = await db.ImprovementActions.SingleAsync(x => x.Title == "MFA for finance");
            a.Status = ImprovementActionStatus.Open;   // reopened in Q3 (the clock reads September)
            a.ClosedAtUtc = null;
            var t = await db.ImprovementActions.SingleAsync(x => x.Title == "Phish training");
            t.TargetDateUtc = Apr(20).AddMonths(4);   // and the other's target pushed out
            await db.SaveChangesAsync();
        }

        var q2 = (await Service().BuildAsync(Q2)).Current;
        q2.ActionsCompleted.Should().Be(before.ActionsCompleted).And.Be(1);
        q2.ActionsOpenAtEnd.Should().Be(before.ActionsOpenAtEnd);
        q2.ActionsPastTargetAtEnd.Should().Be(before.ActionsPastTargetAtEnd).And.Be(1);
    }

    [Fact]
    public async Task A_review_recorded_after_the_quarter_does_not_change_it(/* REV-59 */)
    {
        await SeedAsync();
        await using (var db = new AppDbContext(Options()))
        {
            var b = await db.Cases.FirstAsync(c => c.Title == "Exposure");   // closed in Q2 without a review
            db.PostIncidentReviews.Add(new PostIncidentReview { CaseId = b.Id, WhatHappened = "late", CreatedAtUtc = Apr(20).AddMonths(3), CreatedBy = "ic" });
            await db.SaveChangesAsync();
        }

        (await Service().BuildAsync(Q2)).Current.ClosedWithReview.Should().Be(0, "the review came in Q3");
    }

    [Fact]
    public async Task A_quarter_counts_what_happened_in_it_and_compares_with_the_previous()
    {
        await SeedAsync();
        var targets = new SlaTargets(new Dictionary<(SlaClock, Severity), int>
        {
            [(SlaClock.Containment, Severity.High)] = 4,
            [(SlaClock.Containment, Severity.Critical)] = 4,
        }, 80);

        var r = await Service(targets).BuildAsync(Q2);
        var q2 = r.Current;

        q2.Opened.Should().Be(2, "the drill is excluded and C opened in Q1");
        q2.Closed.Should().Be(1);
        q2.OpenAtEnd.Should().Be(1);
        q2.OpenedByClassification.Should().Equal(new CountBy<Classification?>(Classification.Incident, 1),
            new CountBy<Classification?>(Classification.Breach, 1));
        q2.TimeToDetect.MedianHours.Should().Be(6);
        q2.TimeToContain.Should().Be(new Interval(6, 6, 2));   // 2h and 10h
        q2.Sla.Single(s => s.Clock == SlaClock.Containment).Should().Be(new SlaAttainment(SlaClock.Containment, 1, 1));
        q2.BreachesOpened.Should().Be(1);
        q2.ReportedToRegulators.Should().Be(1);
        q2.ReviewsRecorded.Should().Be(1);
        q2.ActionsOpened.Should().Be(2);
        q2.ActionsCompleted.Should().Be(1);
        q2.ActionsOpenAtEnd.Should().Be(1);
        q2.ActionsPastTargetAtEnd.Should().Be(1);
        q2.ActionAreas.Select(x => x.Key).Should().BeEquivalentTo("Identity", "Awareness");
        r.TopTechniques.Should().ContainSingle(t => t.TechniqueId == "T1566" && t.Cases == 1);

        r.Previous.Opened.Should().Be(1);
        r.Previous.Closed.Should().Be(1);
        r.Period.Previous.Label.Should().Be("Q1 2026");

        // The learning loop: B closed without a review (A's review is on a case still open); one action stays open.
        (q2.Closed, q2.ClosedWithReview).Should().Be((1, 0));
        q2.OpenActionAreas.Should().Equal(new CountBy<string>("Awareness", 1));

        // Containment by severity: the High case met its 4 h, the Critical one missed; Medium has no target.
        q2.ContainmentBySeverity.Should().Contain(new SeverityAttainment(Severity.Critical, 4, 0, 1))
            .And.Contain(new SeverityAttainment(Severity.High, 4, 1, 0))
            .And.Contain(new SeverityAttainment(Severity.Medium, null, 0, 0));
    }

    // The Program overview measures any window the same way, from one read of the cases.
    [Fact]
    public async Task An_archived_case_that_never_closed_is_not_open_at_the_end(/* BUG-211 */)
    {
        await SeedAsync();
        await using (var db = new AppDbContext(Options()))
        {
            var e = Case.Open(2026, 5, "E", "Stale", Classification.Incident, Severity.Low, CaseOrigin.InternalDetection, "ic", Apr(4));
            e.Archive("admin", Apr(6));
            db.Cases.Add(e);
            await db.SaveChangesAsync();
        }

        (await Service().BuildAsync(Q2)).Current.OpenAtEnd.Should().Be(1, "as on the dashboard (BUG-55)");
    }

    [Fact]
    public async Task Any_window_is_measured_like_a_quarter()
    {
        await SeedAsync();

        var snaps = await Service().SnapshotsAsync([
            new ProgramWindow(Q2.StartUtc(TimeZoneInfo.Utc), Q2.EndUtc(TimeZoneInfo.Utc), "Q2"),
            new ProgramWindow(Apr(1), Apr(5), "early April"),
            new ProgramWindow(Feb(1), Feb(28), "February")]);

        snaps.Select(s => s.Opened).Should().Equal(2, 1, 1);
        snaps[1].TimeToContain.Should().Be(new Interval(2, 2, 1), "only A was contained in early April");
        snaps[2].Closed.Should().Be(1);
    }

    [Fact]
    public void The_overview_periods_compare_with_the_stretch_before_and_trend_over_twelve_months()
    {
        var now = new DateTimeOffset(2026, 10, 8, 12, 0, 0, TimeSpan.Zero);

        var quarter = OverviewWindows.For(OverviewPeriod.QuarterToDate, now, TimeZoneInfo.Utc);
        quarter.Current.Should().Be(new ProgramWindow(new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero), now, "Q4 2026 to date"));
        quarter.Previous.Label.Should().Be("Q3 2026");
        quarter.Months.Should().HaveCount(12);
        quarter.Months[^1].EndUtc.Should().Be(now, "the current month runs to now");
        quarter.Months[0].StartUtc.Should().Be(new DateTimeOffset(2025, 11, 1, 0, 0, 0, TimeSpan.Zero));

        var days = OverviewWindows.For(OverviewPeriod.Last30Days, now, TimeZoneInfo.Utc);
        (days.Current.StartUtc, days.Previous.StartUtc, days.Previous.EndUtc).Should().Be((now.AddDays(-30), now.AddDays(-60), now.AddDays(-30)));

        var year = OverviewWindows.For(OverviewPeriod.Last12Months, now, TimeZoneInfo.Utc);
        year.Current.StartUtc.Should().Be(new DateTimeOffset(2025, 11, 1, 0, 0, 0, TimeSpan.Zero));
        year.Previous.StartUtc.Should().Be(new DateTimeOffset(2024, 11, 1, 0, 0, 0, TimeSpan.Zero));
        // REV-55: the same span a year earlier, up to the same point in the month, not twelve whole months.
        year.Previous.EndUtc.Should().Be(now.AddYears(-1));
        (year.Previous.EndUtc - year.Previous.StartUtc).TotalDays.Should().BeApproximately((now - year.Current.StartUtc).TotalDays, 1);

        // A custom range: both days included, compared with the same number of days just before it.
        var custom = OverviewWindows.ForRange(new DateOnly(2026, 7, 1), new DateOnly(2026, 9, 30), now, TimeZoneInfo.Utc);
        custom.Current.Should().Be(new ProgramWindow(new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero), "1 Jul – 30 Sep 2026"));
        custom.Previous.Should().Be(new ProgramWindow(new DateTimeOffset(2026, 3, 31, 0, 0, 0, TimeSpan.Zero),
            custom.Current.StartUtc, "the 92 days before"));
        OverviewWindows.ForRange(new DateOnly(2026, 10, 1), new DateOnly(2026, 10, 8), now, TimeZoneInfo.Utc)
            .Current.EndUtc.Should().Be(now, "today runs to now");
        OverviewWindows.RangeLabel(new DateOnly(2025, 12, 15), new DateOnly(2026, 1, 10)).Should().Be("15 Dec 2025 – 10 Jan 2026");

        var today = new DateOnly(2026, 10, 8);
        OverviewWindows.TryRange("2026-07-01", "2026-09-30", today, out _).Should().Be((new DateOnly(2026, 7, 1), new DateOnly(2026, 9, 30)));
        OverviewWindows.TryRange("2026-10-01", "2026-12-31", today, out _).Should().Be((new DateOnly(2026, 10, 1), today), "it stops at today");
        OverviewWindows.TryRange(null, null, today, out var none).Should().BeNull();
        none.Should().BeNull("no range asked for is not an error");
        OverviewWindows.TryRange("2026-09-30", "2026-07-01", today, out var backwards).Should().BeNull();
        backwards.Should().Be("The start date is after the end date.");
        OverviewWindows.TryRange("2026-07-01", null, today, out var half).Should().BeNull();
        half.Should().Be("Give both dates.");
        OverviewWindows.TryRange("2019-01-01", "2026-01-01", today, out var tooLong).Should().BeNull();
        tooLong.Should().Be("Pick a range of five years or less.");

        OverviewWindows.Parse(null).Should().Be(OverviewPeriod.Last12Months);
        OverviewWindows.Parse("quarter").Should().Be(OverviewPeriod.QuarterToDate);
        OverviewWindows.Key(OverviewPeriod.Last30Days).Should().Be("30d");
    }

    [Fact]
    public async Task Exercises_join_only_when_asked_and_the_csv_carries_both_quarters()
    {
        await SeedAsync();

        var r = await Service().BuildAsync(Q2, includeExercises: true);
        r.Current.Opened.Should().Be(3);

        var csv = ProgramReportService.ToCsv(r, c => c?.ToString() ?? "Complex Event", s => s.ToString());
        csv.Should().Contain("section,metric,Q2 2026,Q1 2026");
        csv.Should().Contain("Volume,Cases opened,3,1");
        csv.Should().Contain("(includes exercise cases)");
        // BUG-77: the page's regulatory-notice and review figures are in the CSV too.
        csv.Should().Contain("Regulatory,Notices inside / outside their window,").And.Contain("Post-incident,Closed cases with a review,");
    }

    [Fact]
    public void Quarters_are_calendar_quarters()
    {
        ProgramPeriod.Containing(new DateTimeOffset(2026, 9, 24, 0, 0, 0, TimeSpan.Zero), TimeZoneInfo.Utc).Should().Be(new ProgramPeriod(2026, 3));
        new ProgramPeriod(2026, 1).Previous.Should().Be(new ProgramPeriod(2025, 4));
        new ProgramPeriod(2026, 4).EndUtc(TimeZoneInfo.Utc).Should().Be(new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero));
        ProgramPeriod.TryCreate(2026, 5).Should().BeNull();
    }

    // Quarters are cut in the reporting time zone, like the dashboard's months: 02:00 UTC on 1 April is still
    // 31 March (EDT), so a case opened then is a Q1 case in New York and a Q2 case in UTC.
    [Fact]
    public async Task Quarters_follow_the_reporting_time_zone()
    {
        await using (var db = new AppDbContext(Options()))
        {
            await db.Database.EnsureCreatedAsync();
            db.Cases.Add(Case.Open(2026, 1, "Edge", "Quarter edge", Classification.Incident, Severity.Low,
                CaseOrigin.InternalDetection, "ic", new DateTimeOffset(2026, 4, 1, 2, 0, 0, TimeSpan.Zero)));
            await db.SaveChangesAsync();
        }

        var eastern = await Service(zone: Eastern).BuildAsync(Q2);
        (eastern.Current.Opened, eastern.Previous.Opened).Should().Be((0, 1));
        (eastern.FirstDay, eastern.LastDay).Should().Be((new DateOnly(2026, 4, 1), new DateOnly(2026, 6, 30)));
        eastern.ZoneLabel.Should().Be("Eastern (New York)");
        ProgramReportService.ToCsv(eastern, c => c?.ToString() ?? "", s => s.ToString())
            .Should().Contain("2026-04-01 to 2026-06-30 (Eastern (New York))");

        var utc = await Service(zone: TimeZoneInfo.Utc).BuildAsync(Q2);
        (utc.Current.Opened, utc.Previous.Opened).Should().Be((1, 0));

        ProgramPeriod.Containing(new DateTimeOffset(2026, 4, 1, 2, 0, 0, TimeSpan.Zero), Eastern).Should().Be(new ProgramPeriod(2026, 1));
        ProgramPeriod.Containing(new DateTimeOffset(2026, 4, 1, 4, 0, 0, TimeSpan.Zero), Eastern).Should().Be(Q2);
    }

    // ---- PROD-15: the scheduled executive report ----

    private sealed class CapturingNotifications : IncidentManager.Application.Abstractions.ICaseNotifications
    {
        public List<ProgramReport> Reports { get; } = [];
        public Task OnExecutiveReportAsync(ProgramReport report, CancellationToken ct = default) { Reports.Add(report); return Task.CompletedTask; }
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnAssignedAsync(Case c, string a, string b, CaseAssignmentRole role, string by, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<IncidentManager.Application.Abstractions.OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<IncidentManager.Application.Abstractions.DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
    }

    [Fact]
    public async Task The_executive_report_goes_once_in_the_first_week_of_a_quarter_with_manager_visibility()
    {
        await SeedAsync();
        await using (var db = new AppDbContext(Options()))
        {
            // A restricted Q2 case: the scheduled report (Manager visibility, like its recipients) still counts it.
            var hidden = Case.Open(2026, 9, "H", "Restricted", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic", Apr(28));
            hidden.IsRestricted = true;
            db.Cases.Add(hidden);
            await db.SaveChangesAsync();
        }
        var sent = new CapturingNotifications();
        var tracker = new IncidentManager.Application.Notifications.ExecutiveReportTracker();
        IncidentManager.Application.Notifications.ExecutiveReportScanner Scanner() =>
            new(new TestDbContextFactory(Options()), new TestSlaTargets(), sent, tracker, _clock);

        _clock.UtcNow = new DateTimeOffset(2026, 7, 20, 0, 0, 0, TimeSpan.Zero);     // too late in Q3
        (await Scanner().ScanAndSendAsync()).Should().BeFalse();

        _clock.UtcNow = new DateTimeOffset(2026, 7, 2, 9, 0, 0, TimeSpan.Zero);      // first week of Q3
        (await Scanner().ScanAndSendAsync()).Should().BeTrue();
        (await Scanner().ScanAndSendAsync()).Should().BeFalse("once per quarter");

        sent.Reports.Should().ContainSingle();
        sent.Reports[0].Period.Should().Be(Q2);
        sent.Reports[0].Current.Opened.Should().Be(3, "A, B and the restricted case; the drill stays out");
    }

    // The quarter turns over at local midnight in the reporting time zone, so the report for the quarter just ended
    // doesn't go out while it's still that quarter in New York.
    [Fact]
    public async Task The_executive_report_waits_for_the_quarter_to_end_in_the_reporting_time_zone()
    {
        await SeedAsync();
        var sent = new CapturingNotifications();
        var tracker = new IncidentManager.Application.Notifications.ExecutiveReportTracker();
        IncidentManager.Application.Notifications.ExecutiveReportScanner Scanner() =>
            new(new TestDbContextFactory(Options()), new TestSlaTargets(), sent, tracker, _clock, new FixedZone(Eastern));

        _clock.UtcNow = new DateTimeOffset(2026, 7, 1, 2, 0, 0, TimeSpan.Zero);      // 22:00 on 30 June in New York
        (await Scanner().ScanAndSendAsync()).Should().BeFalse();

        _clock.UtcNow = new DateTimeOffset(2026, 7, 1, 4, 30, 0, TimeSpan.Zero);     // 00:30 on 1 July in New York
        (await Scanner().ScanAndSendAsync()).Should().BeTrue();
        sent.Reports.Single().Period.Should().Be(Q2);
        sent.Reports.Single().ZoneLabel.Should().Be("Eastern (New York)");
    }

    public void Dispose() => _connection.Dispose();
}
