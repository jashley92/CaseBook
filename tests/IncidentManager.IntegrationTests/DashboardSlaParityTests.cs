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
/// that includes milestones landing exactly on a target.
/// </summary>
public sealed class DashboardSlaParityTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 28, 12, 0, 0, TimeSpan.Zero));

    private static readonly SlaTargets Targets = new(
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
        },
        AtRiskThresholdPercent: 75,
        BreachHours: new Dictionary<(SlaClock, Severity), int>
        {
            [(SlaClock.Containment, Severity.High)] = 12,
            [(SlaClock.Containment, Severity.Low)] = 48,   // breach-only target where the base has none
            [(SlaClock.Resolution, Severity.Critical)] = 48,
            [(SlaClock.Detection, Severity.Critical)] = 1, // ignored: detection has no breach override
        });

    public DashboardSlaParityTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = NewContext();
        db.Database.EnsureCreated();
    }

    // No audit interceptor: the seed controls timestamps directly.
    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options;
    private AppDbContext NewContext() => new(Options());

    private DashboardService NewDashboard(TestCurrentUser user) =>
        new(new TestDbContextFactory(Options()), user, _clock, new TestSlaTargets(Targets), new NotifyOff(),
            new NotificationRuleService(new TestDbContextFactory(Options()), user, _clock));

    [Fact]
    public async Task Database_counts_match_the_in_memory_SlaPolicy_calculation()
    {
        var seeded = await SeedAsync(seed: 8, count: 400);

        foreach (var user in new[]
                 {
                     new TestCurrentUser { UserId = "mgr", RoleSet = [AppRole.Manager] },
                     new TestCurrentUser { UserId = "analyst1", RoleSet = [AppRole.Analyst] },
                 })
        {
            var visible = seeded.Where(c => !c.IsExercise && (user.Has(Permission.ViewAllCases)
                || !c.IsRestricted || c.IncidentCommander == user.UserId || c.Assignments.Any(a => a.UserId == user.UserId))).ToList();
            var expected = Reference(visible, _clock.UtcNow);

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
        var all = Reference(seeded.Where(c => !c.IsExercise).ToList(), _clock.UtcNow);
        new[] { all.AtRisk, all.Breached, all.CMet, all.CMissed, all.RMet, all.RMissed, all.DMet, all.DMissed }
            .Should().OnlyContain(n => n > 0);
    }

    [Fact]
    public async Task Overdue_tasks_on_cases_the_user_cannot_see_are_not_counted()
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

        met.Should().Contain("DATEDIFF_BIG(nanosecond, [c].[DetectedAtUtc], [c].[ContainedAtUtc]) / CAST(100 AS bigint)");
        mean.Should().Contain("DATEDIFF_BIG(nanosecond, [c].[DetectedAtUtc], [c].[ContainedAtUtc])");
        headline.Should().Contain("[c].[DetectedAtUtc] <= @");
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
            if (c.IsRestricted && rng.Next(2) == 0) c.IncidentCommander = "analyst1";

            for (var t = rng.Next(4); t > 0; t--)
                c.ActionItems.Add(new ActionItem
                {
                    Title = "Task",
                    DueAtUtc = rng.Next(5) == 0 ? null : now.AddHours(rng.Next(-300, 300)),
                    Status = (ActionItemStatus)rng.Next(Enum.GetValues<ActionItemStatus>().Length),
                    CreatedBy = "seed",
                    CreatedAtUtc = created,
                });
            cases.Add(c);
        }

        await using var db = NewContext();
        db.Cases.AddRange(cases);
        await db.SaveChangesAsync();
        return cases;
    }

    private sealed record Expected(int AtRisk, int Breached, int CMet, int CMissed, int RMet, int RMissed, int DMet, int DMissed,
        double? MeanContain, double? MeanResolve, int Overdue, IReadOnlyList<TrendPoint> Trend);

    // The pre-F-08 dashboard calculation, verbatim in substance: SlaPolicy over every visible case in memory.
    private static Expected Reference(List<Case> cases, DateTimeOffset now)
    {
        int atRisk = 0, breached = 0, cMet = 0, cMissed = 0, rMet = 0, rMissed = 0, dMet = 0, dMissed = 0;
        foreach (var r in cases)
        {
            var (cont, res) = SlaPolicy.Breakdown(r.Severity, r.Phase, r.DetectedAtUtc, r.ContainedAtUtc, r.ResolvedAtUtc, Targets, now, r.Classification);
            var det = SlaPolicy.EvaluateDetection(r.Severity, r.OccurredAtUtc, r.DetectedAtUtc, Targets);
            if (det.State == SlaState.Met) dMet++; else if (det.State == SlaState.Missed) dMissed++;
            if (cont.State == SlaState.Met) cMet++; else if (cont.State == SlaState.Missed) cMissed++;
            if (res.State == SlaState.Met) rMet++; else if (res.State == SlaState.Missed) rMissed++;
            if (r.Phase != CasePhase.Closed && !r.IsArchived)
            {
                var head = SlaPolicy.Evaluate(r.Severity, r.Phase, r.DetectedAtUtc, r.ContainedAtUtc, r.ResolvedAtUtc, Targets, now, r.Classification).State;
                if (head == SlaState.Breached) breached++; else if (head == SlaState.AtRisk) atRisk++;
            }
        }

        static double? Mean(IEnumerable<double> hours) => hours.Any() ? Math.Round(hours.Average(), 1) : null;
        var meanContain = Mean(cases.Where(c => c.ContainedAtUtc != null && c.DetectedAtUtc != null)
            .Select(c => (c.ContainedAtUtc!.Value - c.DetectedAtUtc!.Value).TotalHours));
        var meanResolve = Mean(cases.Where(c => c.ResolvedAtUtc != null && c.DetectedAtUtc != null)
            .Select(c => (c.ResolvedAtUtc!.Value - c.DetectedAtUtc!.Value).TotalHours));
        var overdue = cases.SelectMany(c => c.ActionItems).Count(a => a.IsOverdue(now));

        var current = new DateTimeOffset(now.Year, now.Month, 1, 0, 0, 0, TimeSpan.Zero);
        var trend = Enumerable.Range(0, 12).Select(i => current.AddMonths(-(11 - i))).Select(start =>
        {
            var end = start.AddMonths(1);
            return new TrendPoint(start.Year, start.Month,
                cases.Count(s => s.CreatedAtUtc >= start && s.CreatedAtUtc < end),
                cases.Count(s => s.ClosedAtUtc is { } c && c >= start && c < end),
                cases.Count(s => s.CreatedAtUtc < end && (s.ClosedAtUtc is null || s.ClosedAtUtc >= end)));
        }).ToList();

        return new Expected(atRisk, breached, cMet, cMissed, rMet, rMissed, dMet, dMissed, meanContain, meanResolve, overdue, trend);
    }

    private sealed class NotifyOff : INotificationDeadlineSettingsProvider
    {
        public NotificationDeadlineSettings Current => NotificationDeadlineSettings.Off;
    }

    public void Dispose() => _connection.Dispose();
}
