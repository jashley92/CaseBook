using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Dashboards;

public sealed record PhaseCount(CasePhase Phase, int Count);

/// <summary>Counts for one month, derived from case open/close timestamps (no snapshots required).</summary>
public sealed record TrendPoint(int Year, int Month, int Opened, int Closed, int OpenAtEnd);

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
    // open cases with a running notification clock (obligation triggered, not yet reported); of those, how
    // many are at-risk / breached. MeanHoursToReport is the detected→reported compliance MTTR.
    bool NotifyDeadlinesEnabled,
    int NotifyAwaitingReport,
    int NotifyAtRisk,
    int NotifyBreached,
    double? MeanHoursToReport,
    IReadOnlyList<PhaseCount> ByPhase,
    IReadOnlyList<TrendPoint> Trend)
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

    public DashboardService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        Sla.ISlaTargetsProvider sla, Compliance.INotificationDeadlineSettingsProvider notify,
        Admin.NotificationRuleService rules)
    {
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

        var openCount = await open.CountAsync(ct);
        var breaches = await open.CountAsync(c => c.Classification == Classification.Breach, ct);
        var incidents = await open.CountAsync(c => c.Classification == Classification.Incident, ct);
        var adverse = await open.CountAsync(c => c.Classification == Classification.AdverseEvent, ct);
        var internalOrigin = await open.CountAsync(c => c.Origin == CaseOrigin.InternalDetection, ct);
        var thirdParty = await open.CountAsync(c => c.Origin == CaseOrigin.ThirdParty, ct);
        var legalReferred = await open.CountAsync(c => c.LegalReferral.IsReferred, ct);

        var now = _clock.UtcNow;
        // Filter on the translatable parts server-side; DateTimeOffset comparison doesn't
        // translate on SQLite (SQL Server handles it natively), so compare the due date in memory.
        var openDueDates = await db.ActionItems.AsNoTracking()
            .Where(a => a.DueAtUtc != null
                        && a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled)
            .Select(a => a.DueAtUtc!.Value)
            .ToListAsync(ct);
        var overdue = openDueDates.Count(d => d < now);

        // One pass over the visible cases against the administered per-severity targets (Sla:*):
        //  • open cases → the headline at-risk/breached signal (the earliest running clock);
        //  • any case that reached a milestone → historical compliance (Met/Missed) per clock.
        // Everything here is settings-aligned — no target is hardcoded in the app or the UI.
        var slaTargets = _sla.Current;
        var slaRows = await cases
            .Select(c => new { c.Severity, c.Phase, c.IsArchived, c.Classification, c.OccurredAtUtc, c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc })
            .ToListAsync(ct);
        int slaAtRisk = 0, slaBreached = 0;
        int cMet = 0, cMissed = 0, rMet = 0, rMissed = 0, dMet = 0, dMissed = 0;
        foreach (var r in slaRows)
        {
            var (cont, res) = Sla.SlaPolicy.Breakdown(
                r.Severity, r.Phase, r.DetectedAtUtc, r.ContainedAtUtc, r.ResolvedAtUtc, slaTargets, now, r.Classification);
            var det = Sla.SlaPolicy.EvaluateDetection(r.Severity, r.OccurredAtUtc, r.DetectedAtUtc, slaTargets);
            if (det.State == Sla.SlaState.Met) dMet++; else if (det.State == Sla.SlaState.Missed) dMissed++;

            if (cont.State == Sla.SlaState.Met) cMet++; else if (cont.State == Sla.SlaState.Missed) cMissed++;
            if (res.State == Sla.SlaState.Met) rMet++; else if (res.State == Sla.SlaState.Missed) rMissed++;

            if (r.Phase != CasePhase.Closed && !r.IsArchived)
            {
                var head = Sla.SlaPolicy
                    .Evaluate(r.Severity, r.Phase, r.DetectedAtUtc, r.ContainedAtUtc, r.ResolvedAtUtc, slaTargets, now, r.Classification)
                    .State;
                if (head == Sla.SlaState.Breached) slaBreached++;
                else if (head == Sla.SlaState.AtRisk) slaAtRisk++;
            }
        }

        var byPhase = await open
            .GroupBy(c => c.Phase)
            .Select(g => new PhaseCount(g.Key, g.Count()))
            .ToListAsync(ct);

        // Mean time-to-contain / resolve over cases that reached those milestones (computed in
        // memory — TimeSpan arithmetic doesn't translate to SQL on all providers).
        var containedPairs = await cases
            .Where(c => c.ContainedAtUtc != null && c.DetectedAtUtc != null)
            .Select(c => new { From = c.DetectedAtUtc!.Value, To = c.ContainedAtUtc!.Value })
            .ToListAsync(ct);
        var resolvedPairs = await cases
            .Where(c => c.ResolvedAtUtc != null && c.DetectedAtUtc != null)
            .Select(c => new { From = c.DetectedAtUtc!.Value, To = c.ResolvedAtUtc!.Value })
            .ToListAsync(ct);

        double? MeanHours(IEnumerable<(DateTimeOffset From, DateTimeOffset To)> pairs)
        {
            var hours = pairs.Select(p => (p.To - p.From).TotalHours).ToList();
            return hours.Count > 0 ? Math.Round(hours.Average(), 1) : null;
        }

        // PROD-07: regulatory notification-deadline aggregates, only when the feature is administered on. One
        // pass over open, not-yet-reported cases whose obligation is triggered (per the configured start
        // basis) and whose data elements trigger a jurisdiction; count the headline at-risk/breached.
        var ndSettings = _notify.Current;
        int notifyAwaiting = 0, notifyAtRisk = 0, notifyBreached = 0;
        double? meanHoursToReport = null;
        if (ndSettings.Enabled)
        {
            var ruleSet = await _rules.LoadRuleSetAsync(ndSettings.DefaultWindowHours, ct);
            var heads = await Compliance.NotificationDeadlineService.OpenHeadlinesAsync(db, open, ndSettings, ruleSet, now, ct);
            notifyAwaiting = heads.Count;
            notifyBreached = heads.Values.Count(h => h.State == Sla.SlaState.Breached);
            notifyAtRisk = heads.Values.Count(h => h.State == Sla.SlaState.AtRisk);

            var reportedPairs = await cases
                .Where(c => c.ReportedAtUtc != null && c.DetectedAtUtc != null)
                .Select(c => new { From = c.DetectedAtUtc!.Value, To = c.ReportedAtUtc!.Value })
                .ToListAsync(ct);
            meanHoursToReport = MeanHours(reportedPairs.Select(p => (p.From, p.To)));
        }

        var trend = await BuildTrendAsync(cases, now, months: 12, ct);

        return new DashboardMetrics(
            openCount, breaches, incidents, adverse, internalOrigin, thirdParty, legalReferred, overdue,
            slaAtRisk, slaBreached,
            cMet, cMissed, rMet, rMissed, dMet, dMissed,
            MeanHours(containedPairs.Select(p => (p.From, p.To))),
            MeanHours(resolvedPairs.Select(p => (p.From, p.To))),
            ndSettings.Enabled, notifyAwaiting, notifyAtRisk, notifyBreached, meanHoursToReport,
            byPhase.OrderBy(p => p.Phase).ToList(),
            trend);
    }

    /// <summary>
    /// A month-by-month trend reconstructed from each case's open (<c>CreatedAtUtc</c>) and close
    /// (<c>ClosedAtUtc</c>) timestamps — so "opened", "closed" and "open at month end" are exact
    /// historical figures without needing stored snapshots. Buckets are computed in memory because
    /// month arithmetic doesn't translate to SQL on all providers.
    /// </summary>
    public static async Task<IReadOnlyList<TrendPoint>> BuildTrendAsync(
        IQueryable<Case> cases, DateTimeOffset now, int months, CancellationToken ct = default)
    {
        var spans = await cases
            .Select(c => new { c.CreatedAtUtc, c.ClosedAtUtc })
            .ToListAsync(ct);

        var current = new DateTimeOffset(now.Year, now.Month, 1, 0, 0, 0, TimeSpan.Zero);
        var starts = Enumerable.Range(0, months)
            .Select(i => current.AddMonths(-(months - 1 - i)))
            .ToList();

        return starts.Select(start =>
        {
            var end = start.AddMonths(1);
            var opened = spans.Count(s => s.CreatedAtUtc >= start && s.CreatedAtUtc < end);
            var closed = spans.Count(s => s.ClosedAtUtc is { } c && c >= start && c < end);
            var openAtEnd = spans.Count(s => s.CreatedAtUtc < end && (s.ClosedAtUtc is null || s.ClosedAtUtc >= end));
            return new TrendPoint(start.Year, start.Month, opened, closed, openAtEnd);
        }).ToList();
    }
}
