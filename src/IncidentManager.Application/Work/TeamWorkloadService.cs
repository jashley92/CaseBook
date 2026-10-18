using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Work;

/// <summary>
/// Leadership view (E-25): how open cases are distributed across the team, so an IC/Manager can rebalance
/// instead of guessing. Reads are need-to-know scoped like everything else — the caller sees the workload
/// over the cases they're entitled to — and this view is gated on <c>ViewAllCases</c>, so its holders see
/// the full team picture. Builds on the assignment data already captured and reuses the E-16 SLA targets.
/// </summary>
public sealed class TeamWorkloadService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ISlaTargetsProvider _sla;

    public TeamWorkloadService(IAppDbContextFactory factory, ICurrentUser user, IClock clock, ISlaTargetsProvider sla)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _sla = sla;
    }

    public async Task<TeamWorkload> GetAsync(CancellationToken ct = default) => await GetAsync(TeamScope.Any, ct);

    /// <summary>CAP-36: the workload over one team's open cases (or those with none), after need-to-know.</summary>
    public async Task<TeamWorkload> GetAsync(TeamScope team, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();

        var rows = (await db.Cases.AsNoTracking().ForUser(_user).InTeam(team).ExcludingExercises() // PROD-43: exclude drills
            .Where(c => c.Phase != CasePhase.Closed && !c.IsArchived)
            .Select(c => new
            {
                c.Severity, c.Phase, c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc, c.CreatedAtUtc,
                // REV-15: last activity is the newest audit entry for the case, as the stale-case reminder reads it. The
                // case row's modified time doesn't move for notes, timeline entries, tasks or hand-offs.
                // C18: not CaseBook's upkeep, which isn't work on the case.
                LastAudit = db.AuditLog.Where(a => a.CaseNumber == c.CaseNumber && a.Reason != Integrity.IntegrityUpkeep.Reason)
                    .Max(a => (DateTimeOffset?)a.AtUtc),
                Workers = c.Assignments
                    .Where(a => a.Role != CaseAssignmentRole.Observer)
                    .Select(a => new WorkloadWorker(a.UserId, a.UserDisplayName, a.Role == CaseAssignmentRole.IncidentCommander))
                    .ToList(),
                c.Classification
            })
            .ToListAsync(ct))
            .Select(c => new WorkloadCaseRow(c.Severity, c.Phase, c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc,
                c.LastAudit is { } a && a > c.CreatedAtUtc ? a : c.CreatedAtUtc, c.Workers, c.Classification))
            .ToList();

        return TeamWorkloadBuilder.Build(rows, _sla.Current, _clock.UtcNow);
    }
}
