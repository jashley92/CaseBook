using FluentAssertions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Dashboards;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// F-08: the dashboard now counts and averages in the database (SlaQueries, DbTime). These tests hold it to the
/// previous in-memory calculation, which ran SlaPolicy over every visible case, across a varied random case set
/// that includes milestones landing exactly on a target. Runs on SQLite (dev) and, when a server is available, on
/// SQL Server (production) — see the two classes at the end of this file.
/// </summary>
public abstract class DashboardSlaParityTests : IDisposable
{
    protected readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 28, 12, 0, 0, TimeSpan.Zero));

    protected static readonly SlaTargets Targets = new(
        new Dictionary<(SlaClock, Severity), int>
        {
            [(SlaClock.Containment, Severity.Critical)] = 4,
            [(SlaClock.Containment, Severity.High)] = 24,
            [(SlaClock.Containment, Severity.Medium)] = 72,
            [(SlaClock.Resolution, Severity.Critical)] = 72,
            [(SlaClock.Resolution, Severity.High)] = 168,
            [(SlaClock.Resolution, Severity.Medium)] = 336,
            [(SlaClock.Resolution, Severity.Low)] = 720,
            [(SlaClock.Detection, Severity.Critical)] = 24,
            [(SlaClock.Detection, Severity.High)] = 48,
            [(SlaClock.Detection, Severity.Low)] = 336,
            [(SlaClock.Containment, Severity.Informational)] = 1, // never applies: Informational carries no SLA
            [(SlaClock.Resolution, Severity.Informational)] = 1,
        },
        AtRiskThresholdPercent: 75,
        BreachHours: new Dictionary<(SlaClock, Severity), int>
        {
            [(SlaClock.Containment, Severity.High)] = 12,
            [(SlaClock.Containment, Severity.Low)] = 48,   // breach-only target where the base has none
            [(SlaClock.Resolution, Severity.Critical)] = 48,
            [(SlaClock.Detection, Severity.Critical)] = 1, // ignored: detection has no breach override
        });

    // No audit interceptor: the seed controls timestamps directly.
    protected abstract DbContextOptions<AppDbContext> Options();
    protected AppDbContext NewContext() => new(Options());

    private static readonly TimeZoneInfo Eastern = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");

    private DashboardService NewDashboard(TestCurrentUser user, SlaTargets? targets = null, TimeZoneInfo? zone = null) =>
        new(new TestDbContextFactory(Options()), user, _clock, new TestSlaTargets(targets ?? Targets), new NotifyOff(),
            new NotificationRuleService(new TestDbContextFactory(Options()), user, _clock), new FixedZone(zone ?? Eastern));

    private static readonly TestCurrentUser[] Viewers =
    [
        new() { UserId = "mgr", RoleSet = [AppRole.Manager] },            // sees every case
        new() { UserId = "analyst1", RoleSet = [AppRole.Analyst] },       // restricted only as IC or assignee
        new() { UserId = "ic1", RoleSet = [AppRole.IncidentCommander] },  // cleared for restricted, not org-wide
    ];

    private static List<Case> VisibleTo(TestCurrentUser user, IEnumerable<Case> cases) => cases.Where(c => !c.IsExercise
        && (user.Has(Permission.ViewAllCases) || user.Has(Permission.ViewRestricted) || !c.IsRestricted
            || c.IncidentCommander == user.UserId || c.Assignments.Any(a => a.UserId == user.UserId))).ToList();

    protected async Task CountsMatchTheInMemoryCalculation()
    {
        var seeded = await SeedAsync(seed: 8, count: 400);

        foreach (var user in Viewers)
        {
            var expected = Reference(VisibleTo(user, seeded), _clock.UtcNow, Targets, Eastern);
            var m = await NewDashboard(user).GetAsync();

            m.SlaAtRisk.Should().Be(expected.AtRisk, user.UserId);
            m.SlaBreached.Should().Be(expected.Breached, user.UserId);
            (m.ContainmentMet, m.ContainmentMissed).Should().Be((expected.CMet, expected.CMissed), user.UserId);
            (m.ResolutionMet, m.ResolutionMissed).Should().Be((expected.RMet, expected.RMissed), user.UserId);
            (m.DetectionMet, m.DetectionMissed).Should().Be((expected.DMet, expected.DMissed), user.UserId);
            m.MeanHoursToContain.Should().Be(expected.MeanContain, user.UserId);
            m.MeanHoursToResolve.Should().Be(expected.MeanResolve, user.UserId);
            m.OverdueActionItems.Should().Be(expected.Overdue, user.UserId);
            m.Trend.Should().Equal(expected.Trend, user.UserId);
        }

        // The case list's "SLA over or at risk" filter uses the same rules, and still applies to archived cases.
        await using (var db = NewContext())
        {
            var listed = await db.Cases.Where(c => c.Phase != CasePhase.Closed)
                .Where(SlaQueries.NeedsAttention(Targets, _clock.UtcNow)).Select(c => c.Id).ToListAsync();
            listed.Should().BeEquivalentTo(seeded.Where(c => c.Phase != CasePhase.Closed && SlaPolicy.Evaluate(c.Severity, c.Phase,
                c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc, Targets, _clock.UtcNow, c.Classification).NeedsAttention).Select(c => c.Id));
        }

        // The random set actually exercises every outcome, so equality above means something.
        var all = Reference(seeded.Where(c => !c.IsExercise).ToList(), _clock.UtcNow, Targets, Eastern);
        new[] { all.AtRisk, all.Breached, all.CMet, all.CMissed, all.RMet, all.RMissed, all.DMet, all.DMissed }
            .Should().OnlyContain(n => n > 0);
        VisibleTo(Viewers[1], seeded).Count.Should().BeLessThan(VisibleTo(Viewers[2], seeded).Count, "the viewers see different sets");
    }

    // Administered targets at their limits: none at all, the at-risk threshold at 1% and 100%, and every target at
    // the one-year maximum. Same seeded cases, same comparison.
    protected async Task SettingsExtremesMatchTheInMemoryCalculation()
    {
        var seeded = await SeedAsync(seed: 21, count: 250);
        var yearLong = Enum.GetValues<SlaClock>().SelectMany(k => Enum.GetValues<Severity>().Select(v => (k, v)))
            .ToDictionary(x => x, _ => SlaPolicy.MaxTargetHours);
        var variants = new Dictionary<string, SlaTargets>
        {
            ["no targets"] = SlaTargets.Empty,
            ["at risk from 1%"] = Targets with { AtRiskThresholdPercent = 1 },
            ["at risk only at 100%"] = Targets with { AtRiskThresholdPercent = 100 },
            ["every target one year"] = new(yearLong, 80, yearLong),
        };
        var manager = Viewers[0];
        foreach (var (name, targets) in variants)
        {
            var expected = Reference(VisibleTo(manager, seeded), _clock.UtcNow, targets, Eastern);
            var m = await NewDashboard(manager, targets).GetAsync();
            (m.SlaAtRisk, m.SlaBreached).Should().Be((expected.AtRisk, expected.Breached), name);
            (m.ContainmentMet, m.ContainmentMissed, m.ResolutionMet, m.ResolutionMissed, m.DetectionMet, m.DetectionMissed)
                .Should().Be((expected.CMet, expected.CMissed, expected.RMet, expected.RMissed, expected.DMet, expected.DMissed), name);
        }
    }

    // Trend months follow the organization's time zone, daylight saving included: 03:00 UTC on 1 February is still
    // 31 January in New York (EST, UTC-5), and 03:30 UTC on 1 July is still 30 June (EDT, UTC-4).
    protected async Task TrendMonthsFollowTheOrganizationTimeZone()
    {
        Case Opened(int seq, DateTimeOffset at) => Case.Open(2026, seq, $"T{seq}", $"T{seq}", Classification.Incident,
            Severity.Low, CaseOrigin.InternalDetection, "s", at);
        await using (var db = NewContext())
        {
            db.Cases.AddRange(Opened(1, new(2026, 2, 1, 3, 0, 0, TimeSpan.Zero)), Opened(2, new(2026, 7, 1, 3, 30, 0, TimeSpan.Zero)),
                Opened(3, new(2026, 7, 1, 4, 0, 0, TimeSpan.Zero)),    // exactly midnight EDT: July
                Opened(4, new(2026, 1, 1, 3, 0, 0, TimeSpan.Zero)));   // 22:00 on 31 December in New York: last year
            await db.SaveChangesAsync();
        }
        var manager = Viewers[0];

        var eastern = (await NewDashboard(manager, zone: Eastern).GetAsync()).Trend;
        eastern.Single(t => t is { Year: 2026, Month: 2 }).Opened.Should().Be(0);
        eastern.Single(t => t is { Year: 2026, Month: 6 }).Opened.Should().Be(1);
        eastern.Single(t => t is { Year: 2026, Month: 7 }).Opened.Should().Be(1);
        eastern.Single(t => t is { Year: 2025, Month: 12 }).Opened.Should().Be(1);
        eastern.Single(t => t is { Year: 2026, Month: 1 }).Opened.Should().Be(1, "only the late-January case");

        var utc = (await NewDashboard(manager, zone: TimeZoneInfo.Utc).GetAsync()).Trend;
        utc.Single(t => t is { Year: 2026, Month: 2 }).Opened.Should().Be(1);
        utc.Single(t => t is { Year: 2026, Month: 7 }).Opened.Should().Be(2);
        utc.Single(t => t is { Year: 2026, Month: 1 }).Opened.Should().Be(1);
        utc.Single(t => t is { Year: 2025, Month: 12 }).Opened.Should().Be(0);
    }

    protected async Task OverdueTasksAreScopedToVisibleCases()
    {
        var now = _clock.UtcNow;
        var visible = Case.Open(2026, 1, "Open", "Open", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "s", now.AddDays(-3));
        var restricted = Case.Open(2026, 2, "Hidden", "Hidden", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "s", now.AddDays(-3));
        restricted.IsRestricted = true;
        var drill = Case.Open(2026, 3, "Drill", "Drill", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "s", now.AddDays(-3), isExercise: true);
        foreach (var c in new[] { visible, restricted, drill })
            c.ActionItems.Add(new ActionItem { Title = "Late", DueAtUtc = now.AddHours(-1), CreatedBy = "s", CreatedAtUtc = now.AddDays(-2) });
        await using (var db = NewContext())
        {
            db.Cases.AddRange(visible, restricted, drill);
            await db.SaveChangesAsync();
        }

        (await NewDashboard(new TestCurrentUser { UserId = "analyst1", RoleSet = [AppRole.Analyst] }).GetAsync())
            .OverdueActionItems.Should().Be(1);
        (await NewDashboard(new TestCurrentUser { UserId = "mgr", RoleSet = [AppRole.Manager] }).GetAsync())
            .OverdueActionItems.Should().Be(2, "a manager sees the restricted case, but drills never count");
    }

    private async Task<List<Case>> SeedAsync(int seed, int count)
    {
        var rng = new Random(seed);
        var now = _clock.UtcNow;
        var phase = typeof(Case).GetProperty(nameof(Case.Phase))!;
        var classes = new Classification?[] { null, Classification.AdverseEvent, Classification.Incident, Classification.Breach };
        var severities = Enum.GetValues<Severity>();
        var phases = Enum.GetValues<CasePhase>();
        DateTimeOffset Hours(DateTimeOffset from, double max) => from.AddTicks((long)(rng.NextDouble() * max * TimeSpan.TicksPerHour));

        var cases = new List<Case>();
        for (var i = 1; i <= count; i++)
        {
            var severity = severities[rng.Next(severities.Length)];
            var classification = classes[rng.Next(classes.Length)];
            var created = now.AddTicks(-(long)(rng.NextDouble() * 500 * TimeSpan.TicksPerDay));
            var c = Case.Open(2026, i, $"C{i}", $"Case {i}", classification, severity, CaseOrigin.InternalDetection,
                "seed", created, isExercise: rng.Next(10) == 0);

            // Recent detections so open clocks land in every state (on track, at risk, breached).
            c.DetectedAtUtc = rng.Next(20) == 0 ? null : rng.Next(3) == 0 ? now.AddTicks(-(long)(rng.NextDouble() * 400 * TimeSpan.TicksPerHour)) : created;
            if (c.DetectedAtUtc is { } detected)
            {
                if (rng.Next(3) > 0) c.OccurredAtUtc = detected.AddTicks(-(long)((rng.NextDouble() * 400 - 20) * TimeSpan.TicksPerHour));
                var cls = classification;
                int? Target(SlaClock clock) => Targets.HoursFor(clock, severity, clock == SlaClock.Detection ? null : cls);
                // A share of milestones land exactly on the target, where met/missed flips.
                DateTimeOffset Reach(SlaClock clock, DateTimeOffset from, double max) =>
                    rng.Next(6) == 0 && Target(clock) is { } h ? detected.AddHours(h) : Hours(from, max);
                if (rng.Next(3) == 0 && Target(SlaClock.Detection) is { } dh) c.OccurredAtUtc = detected.AddHours(-dh);
                if (rng.Next(2) == 0) c.ContainedAtUtc = Reach(SlaClock.Containment, detected, 120);
                if (rng.Next(2) == 0) c.ResolvedAtUtc = Reach(SlaClock.Resolution, c.ContainedAtUtc ?? detected, 900);
                if (rng.Next(4) == 0) c.ReportedAtUtc = Hours(detected, 200);
            }

            var p = phases[rng.Next(phases.Length)];
            phase.SetValue(c, p);
            if (p == CasePhase.Closed || rng.Next(20) == 0) c.ClosedAtUtc = Hours(created, 2000);
            c.IsArchived = rng.Next(15) == 0;
            if (rng.Next(6) == 0) c.IsRestricted = true;
            if (c.IsRestricted && rng.Next(3) == 0) c.IncidentCommander = "analyst1";
            else if (c.IsRestricted && rng.Next(2) == 0) c.Assign("analyst1", "Analyst One", CaseAssignmentRole.Analyst, "seed", created);

            for (var t = rng.Next(4); t > 0; t--)
                c.ActionItems.Add(new ActionItem
                {
                    Title = "Task",
                    DueAtUtc = rng.Next(5) == 0 ? null : now.AddHours(rng.Next(-300, 300)),
                    Status = (ActionItemStatus)rng.Next(Enum.GetValues<ActionItemStatus>().Length),
                    CreatedBy = "seed",
                    CreatedAtUtc = created,
                });
            // Timestamps arrive with assorted offsets (imports, the API); every comparison must use the instant.
            var offset = Offsets[rng.Next(Offsets.Length)];
            c.OccurredAtUtc = c.OccurredAtUtc?.ToOffset(offset);
            c.DetectedAtUtc = c.DetectedAtUtc?.ToOffset(offset);
            c.ContainedAtUtc = c.ContainedAtUtc?.ToOffset(offset);
            cases.Add(c);
        }
        cases.AddRange(EdgeCases(count));

        await using var db = NewContext();
        db.Cases.AddRange(cases);
        await db.SaveChangesAsync();
        return cases;
    }

    private static readonly TimeSpan[] Offsets = [TimeSpan.Zero, TimeSpan.FromHours(-5), TimeSpan.FromHours(-4), new(5, 30, 0)];

    // Deterministic cases at the edges the random set only brushes past. Critical, not a breach: containment 4h,
    // resolution 72h, detection 24h, at risk from 75% (3h / 54h).
    private IEnumerable<Case> EdgeCases(int after)
    {
        var now = _clock.UtcNow;
        var seq = after;
        Case Critical(DateTimeOffset? detected, DateTimeOffset? contained = null, DateTimeOffset? resolved = null,
            DateTimeOffset? occurred = null, Severity severity = Severity.Critical)
        {
            var c = Case.Open(2026, ++seq, $"E{seq}", $"Edge {seq}", Classification.Incident, severity, CaseOrigin.InternalDetection, "seed", now.AddDays(-400));
            (c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc, c.OccurredAtUtc) = (detected, contained, resolved, occurred);
            return c;
        }
        const long tick = 1;

        // Open clocks at the breached and at-risk cutoffs, and one tick inside each.
        foreach (var d in new[] { now.AddHours(-4), now.AddHours(-4).AddTicks(tick), now.AddHours(-3), now.AddHours(-3).AddTicks(tick) })
            yield return Critical(d);
        foreach (var d in new[] { now.AddHours(-72), now.AddHours(-72).AddTicks(tick), now.AddHours(-54), now.AddHours(-54).AddTicks(tick) })
            yield return Critical(d, contained: d.AddHours(1));

        // Milestones one tick either side of each target.
        var t0 = now.AddDays(-30);
        foreach (var delta in new[] { -tick, 0, tick })
        {
            yield return Critical(t0, contained: t0.AddHours(4).AddTicks(delta));
            yield return Critical(t0, resolved: t0.AddHours(72).AddTicks(delta));
            yield return Critical(t0, occurred: t0.AddHours(-24).AddTicks(-delta));
        }

        // Contained or resolved before detection (detected edited later, or bad import data): a negative duration.
        yield return Critical(t0, contained: t0.AddHours(-5), resolved: t0.AddHours(-2));
        // Centuries apart: a mistyped year. SQL Server can't count nanoseconds across ~292 years.
        yield return Critical(t0, occurred: new DateTimeOffset(1725, 6, 1, 0, 0, 0, TimeSpan.Zero));
        yield return Critical(new DateTimeOffset(1725, 6, 1, 0, 0, 0, TimeSpan.Zero), contained: t0, resolved: t0.AddHours(1));
        // Informational never has an SLA, whatever is configured.
        yield return Critical(now.AddHours(-10), contained: now.AddHours(-9), severity: Severity.Informational);

        // A task due exactly now isn't overdue yet; one tick earlier it is.
        var tasks = Critical(now.AddDays(-2));
        foreach (var due in new[] { now, now.AddTicks(-tick) })
            tasks.ActionItems.Add(new ActionItem { Title = "Due", DueAtUtc = due, CreatedBy = "seed", CreatedAtUtc = now.AddDays(-2) });
        yield return tasks;
    }

    private sealed record Expected(int AtRisk, int Breached, int CMet, int CMissed, int RMet, int RMissed, int DMet, int DMissed,
        double? MeanContain, double? MeanResolve, int Overdue, IReadOnlyList<TrendPoint> Trend);

    // The pre-F-08 dashboard calculation, verbatim in substance: SlaPolicy over every visible case in memory.
    private static Expected Reference(List<Case> cases, DateTimeOffset now, SlaTargets targets, TimeZoneInfo zone)
    {
        int atRisk = 0, breached = 0, cMet = 0, cMissed = 0, rMet = 0, rMissed = 0, dMet = 0, dMissed = 0;
        foreach (var r in cases)
        {
            var (cont, res) = SlaPolicy.Breakdown(r.Severity, r.Phase, r.DetectedAtUtc, r.ContainedAtUtc, r.ResolvedAtUtc, targets, now, r.Classification);
            var det = SlaPolicy.EvaluateDetection(r.Severity, r.OccurredAtUtc, r.DetectedAtUtc, targets);
            if (det.State == SlaState.Met) dMet++; else if (det.State == SlaState.Missed) dMissed++;
            if (cont.State == SlaState.Met) cMet++; else if (cont.State == SlaState.Missed) cMissed++;
            if (res.State == SlaState.Met) rMet++; else if (res.State == SlaState.Missed) rMissed++;
            if (r.Phase != CasePhase.Closed && !r.IsArchived)
            {
                var head = SlaPolicy.Evaluate(r.Severity, r.Phase, r.DetectedAtUtc, r.ContainedAtUtc, r.ResolvedAtUtc, targets, now, r.Classification).State;
                if (head == SlaState.Breached) breached++; else if (head == SlaState.AtRisk) atRisk++;
            }
        }

        static double? Mean(IEnumerable<double> hours) => hours.Any() ? Math.Round(hours.Average(), 1) : null;
        var meanContain = Mean(cases.Where(c => c.ContainedAtUtc != null && c.DetectedAtUtc != null)
            .Select(c => (c.ContainedAtUtc!.Value - c.DetectedAtUtc!.Value).TotalHours));
        var meanResolve = Mean(cases.Where(c => c.ResolvedAtUtc != null && c.DetectedAtUtc != null)
            .Select(c => (c.ResolvedAtUtc!.Value - c.DetectedAtUtc!.Value).TotalHours));
        var overdue = cases.SelectMany(c => c.ActionItems).Count(a => a.IsOverdue(now));

        // Calendar months in the organization's zone, each as the UTC instant its local midnight falls on.
        var localNow = TimeZoneInfo.ConvertTime(now, zone);
        var current = new DateTime(localNow.Year, localNow.Month, 1);
        DateTimeOffset Utc(DateTime localMidnight) => new(TimeZoneInfo.ConvertTimeToUtc(localMidnight, zone), TimeSpan.Zero);
        var trend = Enumerable.Range(0, 12).Select(i => current.AddMonths(-(11 - i))).Select(month =>
        {
            var (start, end) = (Utc(month), Utc(month.AddMonths(1)));
            var opened = cases.Where(s => s.CreatedAtUtc >= start && s.CreatedAtUtc < end).ToList();
            var closed = cases.Where(s => s.ClosedAtUtc is { } c && c >= start && c < end).ToList();
            int OpenAt(DateTimeOffset t) => cases.Count(s => s.CreatedAtUtc < t && (s.ClosedAtUtc is null || s.ClosedAtUtc >= t));
            return new TrendPoint(month.Year, month.Month, opened.Count, closed.Count, OpenAt(end), OpenAt(start),
                ClassificationCounts.Of(opened.Select(c => c.Classification)),
                ClassificationCounts.Of(closed.Select(c => c.Classification)));
        }).ToList();

        return new Expected(atRisk, breached, cMet, cMissed, rMet, rMissed, dMet, dMissed, meanContain, meanResolve, overdue, trend);
    }

    private sealed class FixedZone(TimeZoneInfo zone) : IncidentManager.Application.Abstractions.IOrganizationTimeZone
    {
        public TimeZoneInfo Current => zone;
    }

    private sealed class NotifyOff : INotificationDeadlineSettingsProvider
    {
        public NotificationDeadlineSettings Current => NotificationDeadlineSettings.Off;
    }

    public virtual void Dispose() { }
}

/// <summary>F-08 parity on SQLite: the development database and the default test run.</summary>
public sealed class DashboardSlaParitySqliteTests : DashboardSlaParityTests
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");

    public DashboardSlaParitySqliteTests()
    {
        _connection.Open();
        using var db = NewContext();
        db.Database.EnsureCreated();
    }

    protected override DbContextOptions<AppDbContext> Options() =>
        new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options;

    [Fact]
    public Task Database_counts_match_the_in_memory_SlaPolicy_calculation() => CountsMatchTheInMemoryCalculation();

    [Fact]
    public Task Overdue_tasks_on_cases_the_user_cannot_see_are_not_counted() => OverdueTasksAreScopedToVisibleCases();

    [Fact]
    public Task Settings_at_their_limits_match_the_in_memory_calculation() => SettingsExtremesMatchTheInMemoryCalculation();

    [Fact]
    public Task Trend_months_follow_the_organization_time_zone() => TrendMonthsFollowTheOrganizationTimeZone();

    // Production runs on SQL Server, which the SQLite suite never executes; check the translation it would send.
    [Fact]
    public void Sql_Server_translates_the_filters_and_elapsed_time()
    {
        using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlServer("Server=unused;Database=unused").Options);
        var now = _clock.UtcNow;

        var met = db.Cases.Where(SlaQueries.Reached(SlaClock.Containment, met: true, Targets)).Select(c => c.Id).ToQueryString();
        var headline = db.Cases.Where(SlaQueries.Headline(breached: true, Targets, now)).Select(c => c.Id).ToQueryString();
        var mean = db.Cases.Select(c => (double?)IncidentManager.Application.Abstractions.DbTime.TicksBetween(c.DetectedAtUtc, c.ContainedAtUtc)).ToQueryString();

        // Whole seconds plus the sub-second difference: exact to the tick, and no ~292-year nanosecond overflow.
        foreach (var sql in new[] { met, mean })
        {
            sql.Should().Contain("DATEDIFF_BIG(second, [c].[DetectedAtUtc], [c].[ContainedAtUtc])")
                .And.Contain("DATEPART(nanosecond, [c].[ContainedAtUtc]) - DATEPART(nanosecond, [c].[DetectedAtUtc])")
                .And.NotContain("DATEDIFF_BIG(nanosecond");
        }
        headline.Should().Contain("[c].[DetectedAtUtc] <= @");
    }

    public override void Dispose() => _connection.Dispose();
}

/// <summary>
/// F-08 parity on SQL Server 2022, the production database, where the elapsed-time function becomes DATEDIFF_BIG.
/// Runs when <c>CASEBOOK_TEST_SQL</c> names a server (docs/UPGRADE.md; the CI upgrade-path job sets it) and is
/// skipped otherwise. Each test gets its own throwaway database, dropped afterwards.
/// </summary>
public sealed class DashboardSlaParitySqlServerTests : DashboardSlaParityTests
{
    private readonly string? _connectionString;

    public DashboardSlaParitySqlServerTests()
    {
        if (SqlServerFactAttribute.Server is not { } server) return;
        _connectionString = new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(server)
            { InitialCatalog = $"casebook_test_{Guid.NewGuid():N}" }.ConnectionString;
        using var db = NewContext();
        db.Database.EnsureCreated();
    }

    protected override DbContextOptions<AppDbContext> Options() =>
        new DbContextOptionsBuilder<AppDbContext>().UseSqlServer(_connectionString!).Options;

    [SqlServerFact]
    public Task Database_counts_match_the_in_memory_SlaPolicy_calculation() => CountsMatchTheInMemoryCalculation();

    [SqlServerFact]
    public Task Overdue_tasks_on_cases_the_user_cannot_see_are_not_counted() => OverdueTasksAreScopedToVisibleCases();

    [SqlServerFact]
    public Task Settings_at_their_limits_match_the_in_memory_calculation() => SettingsExtremesMatchTheInMemoryCalculation();

    [SqlServerFact]
    public Task Trend_months_follow_the_organization_time_zone() => TrendMonthsFollowTheOrganizationTimeZone();

    public override void Dispose()
    {
        if (_connectionString is null) return;
        using var db = NewContext();
        db.Database.EnsureDeleted();
    }
}
