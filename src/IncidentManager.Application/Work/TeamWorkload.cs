using IncidentManager.Application.Sla;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Work;

/// <summary>A user actively working a case (IC or Analyst; observers are excluded from workload).</summary>
public sealed record WorkloadWorker(string UserId, string DisplayName, bool IsIncidentCommander);

/// <summary>The minimal facts about one open case needed to compute team workload (E-25).</summary>
public sealed record WorkloadCaseRow(
    Severity Severity,
    CasePhase Phase,
    DateTimeOffset? DetectedAtUtc,
    DateTimeOffset? ContainedAtUtc,
    DateTimeOffset? ResolvedAtUtc,
    DateTimeOffset LastActivityUtc,
    IReadOnlyList<WorkloadWorker> Workers);

/// <summary>One analyst's open caseload, broken down by severity and SLA/stale pressure.</summary>
public sealed record AnalystLoad(
    string UserId,
    string DisplayName,
    int Open,
    int AsIncidentCommander,
    int Critical,
    int High,
    int Medium,
    int Low,
    int Informational,
    int SlaAtRisk,
    int SlaBreached,
    int Stale);

/// <summary>The unassigned open queue — cases nobody is actively working.</summary>
public sealed record UnassignedLoad(
    int Open,
    int Critical,
    int High,
    int Medium,
    int Low,
    int Informational,
    int SlaAtRisk,
    int SlaBreached,
    int Stale);

/// <summary>The full team-workload picture for a leadership view.</summary>
public sealed record TeamWorkload(
    IReadOnlyList<AnalystLoad> Analysts,
    UnassignedLoad Unassigned,
    int TotalOpen,
    int AnalystCount);

/// <summary>
/// Aggregates open cases into a per-analyst workload picture plus the unassigned queue. Pure and
/// side-effect free (like <see cref="MetricsCsv"/> / the SLA policy) so the balancing logic is unit
/// tested without a database. A case counts toward every distinct IC/Analyst assigned to it (observers
/// excluded); a case with no such assignee lands in the unassigned queue.
/// </summary>
public static class TeamWorkloadBuilder
{
    /// <summary>An open case with no activity for this many days is flagged stale.</summary>
    public const int StaleDays = 7;

    public static TeamWorkload Build(IReadOnlyList<WorkloadCaseRow> rows, SlaTargets targets, DateTimeOffset nowUtc)
    {
        var staleBefore = nowUtc.AddDays(-StaleDays);
        var byUser = new Dictionary<string, Accumulator>(StringComparer.Ordinal);
        var unassigned = new Accumulator();

        foreach (var row in rows)
        {
            var slaState = SlaPolicy
                .Evaluate(row.Severity, row.Phase, row.DetectedAtUtc, row.ContainedAtUtc, row.ResolvedAtUtc, targets, nowUtc)
                .State;
            var isStale = row.LastActivityUtc < staleBefore;

            if (row.Workers.Count == 0)
            {
                unassigned.Add(row.Severity, slaState, isStale, isIc: false);
                continue;
            }

            // One assignment per user per case is the invariant, but dedupe defensively.
            foreach (var worker in row.Workers.DistinctBy(w => w.UserId))
            {
                if (!byUser.TryGetValue(worker.UserId, out var acc))
                {
                    acc = new Accumulator { DisplayName = worker.DisplayName };
                    byUser[worker.UserId] = acc;
                }
                acc.Add(row.Severity, slaState, isStale, worker.IsIncidentCommander);
            }
        }

        // Heaviest load first, then whoever carries the most SLA pressure — the rebalancing candidates.
        var analysts = byUser
            .Select(kv => kv.Value.ToLoad(kv.Key))
            .OrderByDescending(a => a.Open)
            .ThenByDescending(a => a.SlaBreached + a.SlaAtRisk)
            .ThenBy(a => a.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new TeamWorkload(analysts, unassigned.ToUnassigned(), rows.Count, analysts.Count);
    }

    private sealed class Accumulator
    {
        public string DisplayName = "";
        private int _open, _ic, _crit, _high, _med, _low, _info, _atRisk, _breached, _stale;

        public void Add(Severity severity, SlaState sla, bool stale, bool isIc)
        {
            _open++;
            if (isIc) _ic++;
            switch (severity)
            {
                case Severity.Critical: _crit++; break;
                case Severity.High: _high++; break;
                case Severity.Medium: _med++; break;
                case Severity.Low: _low++; break;
                default: _info++; break;
            }
            if (sla == SlaState.Breached) _breached++;
            else if (sla == SlaState.AtRisk) _atRisk++;
            if (stale) _stale++;
        }

        public AnalystLoad ToLoad(string userId) =>
            new(userId, DisplayName, _open, _ic, _crit, _high, _med, _low, _info, _atRisk, _breached, _stale);

        public UnassignedLoad ToUnassigned() =>
            new(_open, _crit, _high, _med, _low, _info, _atRisk, _breached, _stale);
    }
}
