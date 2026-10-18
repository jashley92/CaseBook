using System.Linq.Expressions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Dashboards;

public sealed record PhaseCount(CasePhase Phase, int Count);

/// <summary>Open cases in one phase: by severity (highest first), the longest any has been in the phase, and how
/// many are past a response target.</summary>
public sealed record PhaseAging(CasePhase Phase, int Count, IReadOnlyList<CountBy<Severity>> BySeverity,
    TimeSpan? LongestInPhase, int OverTarget);

/// <summary>Counts for one month, derived from case open/close timestamps (no snapshots required).</summary>
/// <param name="OpenAtStart">Open when the month began: carried over from earlier months.</param>
/// <param name="OpenedBy">The month's new cases by their classification.</param>
/// <param name="ClosedBy">The month's closed cases by the classification they closed with.</param>
public sealed record TrendPoint(int Year, int Month, int Opened, int Closed, int OpenAtEnd,
    int OpenAtStart = 0, ClassificationCounts? OpenedBy = null, ClassificationCounts? ClosedBy = null);

/// <summary>Cases split by classification; <see cref="Other"/> is any not yet classified (a complex event).</summary>
public sealed record ClassificationCounts(int Breach, int Incident, int AdverseEvent, int Other)
{
    public static ClassificationCounts Of(IEnumerable<Classification?> classifications)
    {
        int b = 0, i = 0, a = 0, o = 0;
        foreach (var c in classifications)
            switch (c)
            {
                case Classification.Breach: b++; break;
                case Classification.Incident: i++; break;
                case Classification.AdverseEvent: a++; break;
                default: o++; break;
            }
        return new(b, i, a, o);
    }
}

public sealed record DashboardMetrics(
    int OpenCount,
    int Breaches,
    int Incidents,
    int AdverseEvents,
    int InternalOrigin,
    int ThirdPartyOrigin,
    int LegalReferred,
    int OverdueActionItems,
    int SlaAtRisk,
    int SlaBreached,
    // Historical SLA compliance over cases that reached each milestone, judged against the administered
    // per-severity targets (Sla:*). Met = reached within target; Missed = reached only after target passed.
    int ContainmentMet,
    int ContainmentMissed,
    int ResolutionMet,
    int ResolutionMissed,
    // PROD-08: detection SLA (occurred → detected) over cases with an occurred time and a Sla:Detection:* target.
    int DetectionMet,
    int DetectionMissed,
    double? MeanHoursToContain,
    double? MeanHoursToResolve,
    // PROD-07: regulatory notification-deadline aggregates (zero/null when the feature is off). Awaiting =
    // cases with a running notification clock (closed ones included, INV-43) (obligation triggered, not yet reported); of those, how
    // many are at-risk / breached. MeanHoursToReport is the detected→reported compliance MTTR.
    bool NotifyDeadlinesEnabled,
    int NotifyAwaitingReport,
    int NotifyAtRisk,
    int NotifyBreached,
    double? MeanHoursToReport,
    IReadOnlyList<PhaseCount> ByPhase,
    IReadOnlyList<TrendPoint> Trend,
    // The reporting time zone the trend's months were cut in, as Administration names it (e.g. "Eastern (New York)").
    string? TrendZone = null,
    // Open breaches that came from a vendor (third-party origin).
    int BreachesAtVendor = 0)
{
    /// <summary>Percent of contained cases that met their per-severity containment target, or null when none had one.</summary>
    public int? ContainmentCompliancePercent => Percent(ContainmentMet, ContainmentMissed);

    /// <summary>Percent of resolved cases that met their per-severity resolution target, or null when none had one.</summary>
    public int? ResolutionCompliancePercent => Percent(ResolutionMet, ResolutionMissed);

    /// <summary>Percent of cases detected within their per-severity detection target, or null when none had one.</summary>
    public int? DetectionCompliancePercent => Percent(DetectionMet, DetectionMissed);

    private static int? Percent(int met, int missed)
        => met + missed == 0 ? null : (int)Math.Round(met * 100.0 / (met + missed));
}

/// <summary>Leadership metrics computed over the caller's visible set of cases.</summary>
public sealed class DashboardService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly Sla.ISlaTargetsProvider _sla;
    private readonly Compliance.INotificationDeadlineSettingsProvider _notify;
    private readonly Admin.NotificationRuleService _rules;
    private readonly IOrganizationTimeZone? _zone;
    private readonly IServerSettingValues? _server;

    public DashboardService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        Sla.ISlaTargetsProvider sla, Compliance.INotificationDeadlineSettingsProvider notify,
        Admin.NotificationRuleService rules, IOrganizationTimeZone? zone = null, IServerSettingValues? server = null)
    {
        _zone = zone;
        _server = server;
        _factory = factory;
        _user = user;
        _clock = clock;
        _sla = sla;
        _notify = notify;
        _rules = rules;
    }

    public async Task<DashboardMetrics> GetAsync(CancellationToken ct = default) => await GetAsync(false, ct);

    /// <param name="includeExercises">Count exercise cases too; by default drills stay out of posture metrics (PROD-43).</param>
    public async Task<DashboardMetrics> GetAsync(bool includeExercises, CancellationToken ct = default) =>
        await GetAsync(includeExercises, withSlaHistory: true, ct);

    /// <param name="includeExercises">As above.</param>
    /// <param name="withSlaHistory">BUG-612: false for a page that shows only the open-case figures (the Cases page's
    /// counts): the all-time SLA met/missed, which loads every case's history, is left at zero.</param>
    public async Task<DashboardMetrics> GetAsync(bool includeExercises, bool withSlaHistory, CancellationToken ct = default) =>
        await GetAsync(includeExercises, withSlaHistory, TeamScope.Any, ct);

    /// <param name="includeExercises">As above.</param>
    /// <param name="withSlaHistory">As above.</param>
    /// <param name="team">CAP-36: only one team's cases (or those with none), by the team each case belongs to now; applied
    /// after need-to-know, so it never shows a figure from a case the caller can't see.</param>
    public async Task<DashboardMetrics> GetAsync(bool includeExercises, bool withSlaHistory, TeamScope team, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var cases = db.Cases.AsNoTracking().ForUser(_user).InTeam(team);
        if (!includeExercises) cases = cases.ExcludingExercises();

        var open = cases.Where(c => c.Phase != CasePhase.Closed && !c.IsArchived);
        var now = _clock.UtcNow;
        var slaTargets = _sla.Current;

        // F-08: the case-level figures come from two scans, each a single SELECT of conditional aggregates (OneScan),
        // so nothing loads a row per case and no figure costs its own table scan. Open-case figures scan only the open
        // cases (a few percent of the table); the historical ones scan every visible case.
        var openScan = new OneScan<Case>();
        var openCount = openScan.Count(c => true);
        var breaches = openScan.Count(c => c.Classification == Classification.Breach);
        var incidents = openScan.Count(c => c.Classification == Classification.Incident);
        var adverse = openScan.Count(c => c.Classification == Classification.AdverseEvent);
        var internalOrigin = openScan.Count(c => c.Origin == CaseOrigin.InternalDetection);
        var thirdParty = openScan.Count(c => c.Origin == CaseOrigin.ThirdParty);
        var breachesAtVendor = openScan.Count(c => c.Classification == Classification.Breach && c.Origin == CaseOrigin.ThirdParty);

        // SLA against the administered per-severity targets (Sla:*), via SlaQueries (the SlaPolicy rules as filters):
        //  • open cases → the headline at-risk/breached signal (the earliest running clock);
        //  • any case that reached a milestone → historical compliance (Met/Missed) per clock.
        // Everything here is settings-aligned — no target is hardcoded in the app or the UI.
        var slaBreached = openScan.Count(Sla.SlaQueries.Headline(breached: true, slaTargets, now));
        var slaAtRisk = openScan.Count(Sla.SlaQueries.Headline(breached: false, slaTargets, now));
        var phaseCounts = Enum.GetValues<CasePhase>().Where(p => p != CasePhase.Closed)
            .Select(p => (Phase: p, Count: openScan.Count(c => c.Phase == p))).ToList();
        await openScan.RunAsync(open, ct);

        // BUG-588 (owner's decision): historical compliance judges each milestone as the program report judged it in the
        // quarter it was reached (PeriodSla): on the severity and class the case had at that quarter's end, against the
        // targets in force when it was reached, and not the detection clock from an approximate start (BUG-583).
        var (cMet, cMissed, rMet, rMissed, dMet, dMissed) = withSlaHistory ? await AllTimeSlaAsync(db, cases, slaTargets, ct) : default;

        var historyScan = new OneScan<Case>();
        // Mean time-to-contain / resolve over cases that reached those milestones.
        // BUG-165: a case that didn't need containment isn't in time-to-contain.
        var meanToContainTicks = historyScan.Average(c => c.ContainedAtUtc != null && c.DetectedAtUtc != null && c.ContainmentNotNeededReason == null
            ? (double?)DbTime.TicksBetween(c.DetectedAtUtc, c.ContainedAtUtc) : null);
        var meanToResolveTicks = historyScan.Average(c => c.ResolvedAtUtc != null && c.DetectedAtUtc != null
            ? (double?)DbTime.TicksBetween(c.DetectedAtUtc, c.ResolvedAtUtc) : null);
        await historyScan.RunAsync(cases, ct);

        var byPhase = phaseCounts.Where(p => p.Count() > 0).Select(p => new PhaseCount(p.Phase, p.Count())).ToList();
        var meanToContain = MeanHours(meanToContainTicks());
        var meanToResolve = MeanHours(meanToResolveTicks());

        // Legal referral lives in a grouped (owned) property that EF can't read inside the single-scan aggregate.
        var legalReferred = await open.CountAsync(c => c.LegalReferral.IsReferred, ct);

        // Overdue tasks, on the caller's visible, non-exercise open cases only (BUG-12).
        var overdue = await open.SelectMany(c => c.ActionItems).CountAsync(a =>
            a.DueAtUtc != null && a.DueAtUtc < now
            && a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled, ct);

        static double? MeanHours(double? meanTicks)
            => meanTicks is { } t ? Math.Round(t / TimeSpan.TicksPerHour, 1) : null;

        // PROD-07: regulatory notification-deadline aggregates, only when the feature is administered on. One
        // pass over not-yet-reported cases whose obligation is triggered (per the configured start basis) and
        // whose data elements trigger a jurisdiction; count the headline at-risk/breached. INV-43: closed cases
        // count too — closing a case doesn't answer its notification, so the watch continues until one is recorded.
        var ndSettings = _notify.Current;
        int notifyAwaiting = 0, notifyAtRisk = 0, notifyBreached = 0;
        double? meanHoursToReport = null;
        if (ndSettings.Enabled)
        {
            var ruleSet = await _rules.LoadRuleSetAsync(ndSettings.DefaultWindowHours, ct);
            var heads = await Compliance.NotificationDeadlineService.OpenHeadlinesAsync(db, cases.Where(c => !c.IsArchived), ndSettings, ruleSet, now, ct);
            notifyAwaiting = heads.Count;
            notifyBreached = heads.Values.Count(h => h.State == Sla.SlaState.Breached);
            notifyAtRisk = heads.Values.Count(h => h.State == Sla.SlaState.AtRisk);

            meanHoursToReport = MeanHours(await cases
                .Where(c => c.ReportedAtUtc != null && c.DetectedAtUtc != null)
                .Select(c => (double?)DbTime.TicksBetween(c.DetectedAtUtc, c.ReportedAtUtc))
                .AverageAsync(ct));
        }

        var trend = await BuildTrendAsync(cases, now, months: 12, _zone?.Current ?? TimeZoneInfo.Utc, ct);

        return new DashboardMetrics(
            openCount(), breaches(), incidents(), adverse(), internalOrigin(), thirdParty(), legalReferred, overdue,
            slaAtRisk(), slaBreached(),
            cMet, cMissed, rMet, rMissed, dMet, dMissed,
            meanToContain, meanToResolve,
            ndSettings.Enabled, notifyAwaiting, notifyAtRisk, notifyBreached, meanHoursToReport,
            byPhase.OrderBy(p => p.Phase).ToList(),
            trend,
            Admin.SettingsCatalog.TimeZoneLabel(_zone?.Current ?? TimeZoneInfo.Utc),
            breachesAtVendor());
    }

    /// <summary>
    /// BUG-588: met and missed per clock over every visible case that reached a milestone, each judged as the program
    /// report's quarter it was reached in judges it (PeriodSla, PeriodHistory.QuarterEnd), so the two agree. Loads only the
    /// cases with a milestone; the judging is in memory (DateTimeOffset arithmetic stays off SQLite, F-08).
    /// </summary>
    private async Task<(int CMet, int CMissed, int RMet, int RMissed, int DMet, int DMissed)> AllTimeSlaAsync(IAppDbContext db,
        IQueryable<Case> cases, Sla.SlaTargets current, CancellationToken ct)
    {
        // BUG-612: today's severity doesn't pre-filter: a case downgraded to Informational since is judged on the severity
        // it had at the quarter's end, as the report judges it (PeriodSla gives Informational no target).
        var reached = cases.Where(c => c.DetectedAtUtc != null
                                       && (c.ContainedAtUtc != null || c.ResolvedAtUtc != null || c.OccurredAtUtc != null));
        var rows = await reached.Select(c => new
        {
            c.Id, c.Severity, c.Classification, c.Phase, c.Origin,
            c.OccurredAtUtc, c.DetectedAtUtc, c.ContainedAtUtc, NotNeeded = c.ContainmentNotNeededReason != null, c.ResolvedAtUtc
        }).ToListAsync(ct);
        if (rows.Count == 0) return default;
        var history = await TransitionHistory.LoadAsync(db, reached.Select(c => c.Id), ct);
        Func<DateTimeOffset, Sla.SlaTargets> targetsAt = _ => current;
        if (_server is { } server) targetsAt = (await Sla.SlaTargetHistory.LoadAsync(db, server.ValueOf, ct)).At;
        var occurred = rows.ToDictionary(r => r.Id, r => r.OccurredAtUtc);
        var approximate = (await AttackHistory.LoadAsync(db, reached.Where(c => c.OccurredAtUtc != null), withTrails: false, ct))
            .ApproximateStarts(DateTimeOffset.MaxValue, rows.ToDictionary(r => r.Id, r => r.Origin), id => occurred.GetValueOrDefault(id));
        var zone = _zone?.Current ?? TimeZoneInfo.Utc;

        int cMet = 0, cMissed = 0, rMet = 0, rMissed = 0, dMet = 0, dMissed = 0;
        foreach (var r in rows)
        {
            var stamps = new CaseStamps(r.OccurredAtUtc, r.DetectedAtUtc, r.ContainedAtUtc, r.NotNeeded, r.ResolvedAtUtc, null);
            (Sla.SlaStatus C, Sla.SlaStatus R, Sla.SlaStatus D) JudgedIn(DateTimeOffset reachedAt)
            {
                var end = PeriodHistory.QuarterEnd(reachedAt, zone);
                return PeriodSla.Judge(history.SevAt(r.Id, end, r.Severity), history.ClassAt(r.Id, end, r.Classification), r.Phase,
                    stamps, targetsAt, end, approximate.Contains(r.Id));
            }
            if (stamps.ContainedIfNeeded is { } contained) Count(JudgedIn(contained).C.State, ref cMet, ref cMissed);
            if (stamps.ResolvedAtUtc is { } resolved) Count(JudgedIn(resolved).R.State, ref rMet, ref rMissed);
            if (stamps.DetectedAtUtc is { } detected) Count(JudgedIn(detected).D.State, ref dMet, ref dMissed);
        }
        return (cMet, cMissed, rMet, rMissed, dMet, dMissed);

        static void Count(Sla.SlaState state, ref int met, ref int missed)
        {
            if (state == Sla.SlaState.Met) met++;
            else if (state == Sla.SlaState.Missed) missed++;
        }
    }

    /// <summary>
    /// Where open cases stand: per phase, the count by severity, how long the longest-waiting case has been in that
    /// phase (since it entered it, by the effective time of the change), and how many are past a response target.
    /// </summary>
    public async Task<IReadOnlyList<PhaseAging>> PhaseAgingAsync(bool includeExercises = false, CancellationToken ct = default) =>
        await PhaseAgingAsync(includeExercises, TeamScope.Any, ct);

    /// <summary>As above, for one team's cases (CAP-36).</summary>
    public async Task<IReadOnlyList<PhaseAging>> PhaseAgingAsync(bool includeExercises, TeamScope team, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var cases = db.Cases.AsNoTracking().ForUser(_user).InTeam(team).Where(c => c.Phase != CasePhase.Closed && !c.IsArchived);
        if (!includeExercises) cases = cases.ExcludingExercises();
        var now = _clock.UtcNow;
        var targets = _sla.Current;

        var open = await cases.Select(c => new { c.Id, c.Phase, c.Severity, c.Classification, c.CreatedAtUtc,
            c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc }).ToListAsync(ct);
        var ids = cases.Select(c => c.Id);
        var entered = (await db.StatusChanges.AsNoTracking().Where(s => ids.Contains(s.CaseId))
                .Select(s => new { s.CaseId, s.To, s.ChangedAtUtc, s.EffectiveAtUtc }).ToListAsync(ct))
            .GroupBy(s => (s.CaseId, s.To))
            .ToDictionary(g => g.Key, g => g.Max(s => s.EffectiveAtUtc ?? s.ChangedAtUtc));

        return Enum.GetValues<CasePhase>().Where(p => p != CasePhase.Closed).Select(p =>
        {
            var inPhase = open.Where(c => c.Phase == p).ToList();
            var since = inPhase.Select(c => entered.TryGetValue((c.Id, p), out var t) ? t : c.CreatedAtUtc).ToList();
            var over = inPhase.Count(c => Sla.SlaPolicy.Evaluate(c.Severity, c.Phase, c.DetectedAtUtc, c.ContainedAtUtc,
                c.ResolvedAtUtc, targets, now, c.Classification).State == Sla.SlaState.Breached);
            return new PhaseAging(p, inPhase.Count,
                Enum.GetValues<Severity>().OrderByDescending(s => s).Select(s => new CountBy<Severity>(s, inPhase.Count(c => c.Severity == s))).ToList(),
                since.Count == 0 ? null : now - since.Min(), over);
        }).ToList();
    }

    /// <summary>
    /// A month-by-month trend reconstructed from each case's open (<c>CreatedAtUtc</c>) and close
    /// (<c>ClosedAtUtc</c>) timestamps — so "opened", "closed" and "open at month end" are exact
    /// historical figures without needing stored snapshots. Months are calendar months in the organization's
    /// reporting time zone (<paramref name="zone"/>). F-08: only cases opened or closed inside the window are
    /// loaded (two timestamps each); everything opened earlier and still open is one count.
    /// </summary>
    public static async Task<IReadOnlyList<TrendPoint>> BuildTrendAsync(
        IQueryable<Case> cases, DateTimeOffset now, int months, TimeZoneInfo zone, CancellationToken ct = default)
    {
        var (year, month) = ZonedMonths.Of(now, zone);
        var current = new DateTime(year, month, 1);
        var monthStarts = Enumerable.Range(0, months + 1).Select(i => current.AddMonths(i - (months - 1))).ToList();
        var bounds = monthStarts.Select(m => ZonedMonths.StartUtc(m.Year, m.Month, zone)).ToList();
        var windowStart = bounds[0];

        // WF-78: past months as the record stood then (the program report's rule, WF-38): a case closed in June and reopened
        // in October still closed in June, and its classification is the one it had when it closed (a closed case can still
        // be lowered, BUG-107). So a case touched by a closure in the window comes with its closure and class history.
        var spans = await cases
            .Where(c => c.CreatedAtUtc >= windowStart || c.ClosedAtUtc >= windowStart
                        || c.StatusChanges.Any(s => (s.To == CasePhase.Closed || s.From == CasePhase.Closed) && s.ChangedAtUtc >= windowStart)
                        || c.TimeCorrections.Any(x => x.CreatedAtUtc >= windowStart))   // BUG-584: a close re-dated since
            .Select(c => new
            {
                c.Id, c.CreatedAtUtc, c.ClosedAtUtc, c.Classification, c.IsArchived,
                Closures = c.StatusChanges.Where(s => s.To == CasePhase.Closed || s.From == CasePhase.Closed)
                    .Select(s => new PhaseChangeRow(s.Id, s.CaseId, s.From, s.To, s.EffectiveAtUtc ?? s.ChangedAtUtc, s.ChangedAtUtc)).ToList(),
                Classes = c.ClassificationChanges
                    .Select(s => new ClassChangeRow(s.Id, s.CaseId, s.From, s.To, s.EffectiveAtUtc ?? s.ChangedAtUtc, s.ChangedAtUtc)).ToList(),
                Corrections = c.TimeCorrections.Select(x => new CorrectionRow(x.ChangeId, x.FromEffectiveUtc, x.CreatedAtUtc)).ToList(),
            })
            .ToListAsync(ct);
        var inSpans = spans.Select(s => s.Id).ToList();
        // BUG-55: an archived case that was never closed is out of the open count, as on the dashboard's Open tile.
        var carriedOpen = await cases.CountAsync(c => c.CreatedAtUtc < windowStart && c.ClosedAtUtc == null && !c.IsArchived
                                                      && !inSpans.Contains(c.Id), ct);

        // In recording order (WF-97): the order the states followed each other, whatever dates they carry.
        // BUG-584: each month as the record stood at its end, with the transition-time corrections made since undone.
        var history = new TransitionHistory(spans.SelectMany(s => s.Closures), spans.SelectMany(s => s.Classes), [],
            spans.SelectMany(s => s.Corrections));
        bool ClosedAt(Guid id, DateTimeOffset? closedNow, DateTimeOffset t) => history.ClosedAt(id, t, closedNow);

        int OpenAt(DateTimeOffset t) => carriedOpen
            + spans.Count(s => s.CreatedAtUtc < t && !ClosedAt(s.Id, s.ClosedAtUtc, t) && !(s.ClosedAtUtc is null && s.IsArchived));

        return Enumerable.Range(0, months).Select(i =>
        {
            var (start, end) = (bounds[i], bounds[i + 1]);
            var opened = spans.Where(s => s.CreatedAtUtc >= start && s.CreatedAtUtc < end).ToList();
            var closed = spans.SelectMany(s => history.ClosedTimes(s.Id, end, s.ClosedAtUtc).Where(c => c >= start && c < end)
                    .Take(1).Select(c => history.ClassAt(s.Id, c, s.Classification, inclusive: true, asOf: end)))
                .ToList();
            return new TrendPoint(monthStarts[i].Year, monthStarts[i].Month, opened.Count, closed.Count, OpenAt(end),
                OpenAt(start), ClassificationCounts.Of(opened.Select(s => history.ClassAt(s.Id, end, s.Classification, inclusive: true))),
                ClassificationCounts.Of(closed));
        }).ToList();
    }
}
