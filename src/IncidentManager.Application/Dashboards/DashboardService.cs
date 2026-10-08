using System.Linq.Expressions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Dashboards;

public sealed record PhaseCount(CasePhase Phase, int Count);

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
    string? TrendZone = null)
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

    public DashboardService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        Sla.ISlaTargetsProvider sla, Compliance.INotificationDeadlineSettingsProvider notify,
        Admin.NotificationRuleService rules, IOrganizationTimeZone? zone = null)
    {
        _zone = zone;
        _factory = factory;
        _user = user;
        _clock = clock;
        _sla = sla;
        _notify = notify;
        _rules = rules;
    }

    public async Task<DashboardMetrics> GetAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var cases = db.Cases.AsNoTracking().ForUser(_user).ExcludingExercises(); // PROD-43: drills stay out of posture metrics

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

        // SLA against the administered per-severity targets (Sla:*), via SlaQueries (the SlaPolicy rules as filters):
        //  • open cases → the headline at-risk/breached signal (the earliest running clock);
        //  • any case that reached a milestone → historical compliance (Met/Missed) per clock.
        // Everything here is settings-aligned — no target is hardcoded in the app or the UI.
        var slaBreached = openScan.Count(Sla.SlaQueries.Headline(breached: true, slaTargets, now));
        var slaAtRisk = openScan.Count(Sla.SlaQueries.Headline(breached: false, slaTargets, now));
        var phaseCounts = Enum.GetValues<CasePhase>().Where(p => p != CasePhase.Closed)
            .Select(p => (Phase: p, Count: openScan.Count(c => c.Phase == p))).ToList();
        await openScan.RunAsync(open, ct);

        var historyScan = new OneScan<Case>();
        // Missed = judged (reached, with a target) − met: one elapsed-time calculation per clock per row, not two.
        (Func<int> Met, Func<int> Missed) MetMissed(Sla.SlaClock clock)
        {
            var met = historyScan.Count(Sla.SlaQueries.Reached(clock, met: true, slaTargets));
            var judged = historyScan.Count(Sla.SlaQueries.Judged(clock, slaTargets));
            return (met, () => judged() - met());
        }
        var (cMet, cMissed) = MetMissed(Sla.SlaClock.Containment);
        var (rMet, rMissed) = MetMissed(Sla.SlaClock.Resolution);
        var (dMet, dMissed) = MetMissed(Sla.SlaClock.Detection);
        // Mean time-to-contain / resolve over cases that reached those milestones.
        var meanToContainTicks = historyScan.Average(c => c.ContainedAtUtc != null && c.DetectedAtUtc != null
            ? (double?)DbTime.TicksBetween(c.DetectedAtUtc, c.ContainedAtUtc) : null);
        var meanToResolveTicks = historyScan.Average(c => c.ResolvedAtUtc != null && c.DetectedAtUtc != null
            ? (double?)DbTime.TicksBetween(c.DetectedAtUtc, c.ResolvedAtUtc) : null);
        await historyScan.RunAsync(cases, ct);

        var byPhase = phaseCounts.Where(p => p.Count() > 0).Select(p => new PhaseCount(p.Phase, p.Count())).ToList();
        var meanToContain = MeanHours(meanToContainTicks());
        var meanToResolve = MeanHours(meanToResolveTicks());

        // Legal referral lives in a grouped (owned) property that EF can't read inside the single-scan aggregate.
        var legalReferred = await open.CountAsync(c => c.LegalReferral.IsReferred, ct);

        // Overdue tasks, on the caller's visible, non-exercise cases only.
        var overdue = await cases.SelectMany(c => c.ActionItems).CountAsync(a =>
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
            cMet(), cMissed(), rMet(), rMissed(), dMet(), dMissed(),
            meanToContain, meanToResolve,
            ndSettings.Enabled, notifyAwaiting, notifyAtRisk, notifyBreached, meanHoursToReport,
            byPhase.OrderBy(p => p.Phase).ToList(),
            trend,
            Admin.SettingsCatalog.TimeZoneLabel(_zone?.Current ?? TimeZoneInfo.Utc));
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

        var carriedOpen = await cases.CountAsync(c => c.CreatedAtUtc < windowStart && c.ClosedAtUtc == null, ct);
        // A closed case's classification is the one it closed with: closing ends reclassification.
        var spans = await cases
            .Where(c => c.CreatedAtUtc >= windowStart || c.ClosedAtUtc >= windowStart)
            .Select(c => new { c.CreatedAtUtc, c.ClosedAtUtc, c.Classification })
            .ToListAsync(ct);

        int OpenAt(DateTimeOffset t) => carriedOpen
            + spans.Count(s => s.CreatedAtUtc < t && (s.ClosedAtUtc is null || s.ClosedAtUtc >= t));

        return Enumerable.Range(0, months).Select(i =>
        {
            var (start, end) = (bounds[i], bounds[i + 1]);
            var opened = spans.Where(s => s.CreatedAtUtc >= start && s.CreatedAtUtc < end).ToList();
            var closed = spans.Where(s => s.ClosedAtUtc is { } c && c >= start && c < end).ToList();
            return new TrendPoint(monthStarts[i].Year, monthStarts[i].Month, opened.Count, closed.Count, OpenAt(end),
                OpenAt(start), ClassificationCounts.Of(opened.Select(s => s.Classification)),
                ClassificationCounts.Of(closed.Select(s => s.Classification)));
        }).ToList();
    }
}
