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
    double? MeanHoursToContain,
    double? MeanHoursToResolve,
    IReadOnlyList<PhaseCount> ByPhase,
    IReadOnlyList<TrendPoint> Trend);

/// <summary>Leadership metrics computed over the caller's visible set of cases.</summary>
public sealed class DashboardService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly Sla.ISlaTargetsProvider _sla;

    public DashboardService(IAppDbContextFactory factory, ICurrentUser user, IClock clock, Sla.ISlaTargetsProvider sla)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _sla = sla;
    }

    public async Task<DashboardMetrics> GetAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var cases = db.Cases.AsNoTracking().ForUser(_user);

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

        // SLA at-risk/breached over open cases, evaluated against the administered per-severity targets.
        var slaTargets = _sla.Current;
        var slaRows = await open
            .Select(c => new { c.Severity, c.Phase, c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc })
            .ToListAsync(ct);
        int slaAtRisk = 0, slaBreached = 0;
        foreach (var r in slaRows)
        {
            var state = Sla.SlaPolicy
                .Evaluate(r.Severity, r.Phase, r.DetectedAtUtc, r.ContainedAtUtc, r.ResolvedAtUtc, slaTargets, now)
                .State;
            if (state == Sla.SlaState.Breached) slaBreached++;
            else if (state == Sla.SlaState.AtRisk) slaAtRisk++;
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

        var trend = await BuildTrendAsync(cases, now, months: 12, ct);

        return new DashboardMetrics(
            openCount, breaches, incidents, adverse, internalOrigin, thirdParty, legalReferred, overdue,
            slaAtRisk, slaBreached,
            MeanHours(containedPairs.Select(p => (p.From, p.To))),
            MeanHours(resolvedPairs.Select(p => (p.From, p.To))),
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
