using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.StageGates;

/// <summary>Evaluates a case against the active stage gate for a given transition (C-07).</summary>
public interface IStageGateEvaluator
{
    Task<GateEvaluation> EvaluateAsync(IAppDbContext db, Guid caseId, StageGateTrigger trigger,
        CancellationToken ct = default);
}

public sealed class StageGateEvaluator : IStageGateEvaluator
{
    public async Task<GateEvaluation> EvaluateAsync(IAppDbContext db, Guid caseId, StageGateTrigger trigger,
        CancellationToken ct = default)
    {
        var gate = await db.StageGates.AsNoTracking()
            .Include(g => g.Requirements)
            .Where(g => g.IsActive && g.Trigger == trigger)
            .FirstOrDefaultAsync(ct);

        // A gate is "in force" when it has requirements or requires commentary — a commentary-only gate
        // still gates the transition.
        if (gate is null || (gate.Requirements.Count == 0 && gate.CommentaryMinLength == 0))
            return GateEvaluation.None(trigger);

        var facts = await BuildFactsAsync(db, caseId, ct);

        var results = gate.Requirements
            .OrderBy(r => r.Order)
            .Select(r => new GateRequirementResult(
                r.Id, r.Order, r.Kind, r.CheckKey, r.Label, r.IsBlocking,
                MachineSatisfied: r.Kind == GateRequirementKind.MachineCheck
                    && GateCheckRegistry.IsSatisfied(r.CheckKey, facts, r.CheckParam)))
            .ToList();

        return new GateEvaluation(true, trigger, gate.Name, results, gate.CommentaryMinLength);
    }

    private static async Task<GateCaseFacts> BuildFactsAsync(IAppDbContext db, Guid caseId, CancellationToken ct)
    {
        // Scalar facts straight off the case row; collection facts as counts. AsNoTracking so a
        // concurrently-tracked, not-yet-saved mutation on the same context isn't reflected — the gate
        // judges persisted state.
        var c = await db.Cases.AsNoTracking()
            .Where(x => x.Id == caseId)
            .Select(x => new
            {
                HasSummary = x.Summary != null && x.Summary != "",
                HasAffectedCount = x.AffectedIndividualsCount != null,
                AffectedIndividualsCount = x.AffectedIndividualsCount ?? 0,
                HasDataElements = x.DataElements.Any(),
                HasAffectedStates = x.AffectedStates != null && x.AffectedStates != "",
                HasDetectionCaseId = x.DetectionCaseId != null && x.DetectionCaseId != "",
                HasIncidentCommander = x.IncidentCommander != null && x.IncidentCommander != ""
            })
            .FirstOrDefaultAsync(ct);

        if (c is null)
            return new GateCaseFacts(false, false, false, false, false, 0, 0, 0, 0, false);

        var entityCount = await db.CaseEntities.CountAsync(e => e.CaseId == caseId, ct);
        var maliciousCount = await db.CaseEntities
            .CountAsync(e => e.CaseId == caseId && e.Disposition == EntityDisposition.Malicious, ct);
        var evidenceCount = await db.Evidence.CountAsync(e => e.CaseId == caseId, ct);
        var reportCount = await db.Reports.CountAsync(r => r.CaseId == caseId, ct);

        return new GateCaseFacts(
            c.HasSummary, c.HasAffectedCount, c.HasDataElements, c.HasAffectedStates, c.HasDetectionCaseId,
            entityCount, maliciousCount, evidenceCount, reportCount, c.HasIncidentCommander,
            c.AffectedIndividualsCount);
    }
}
