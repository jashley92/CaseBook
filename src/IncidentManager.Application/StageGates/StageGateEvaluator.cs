using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.StageGates;

/// <summary>Evaluates a case against the active stage gate for a given transition (C-07).</summary>
public interface IStageGateEvaluator
{
    Task<GateEvaluation> EvaluateAsync(IAppDbContext db, Guid caseId, StageGateTrigger trigger,
        bool summaryProvided = false, CancellationToken ct = default);

    /// <summary>
    /// BUG-61: a case being created, judged from the object itself (it isn't in the database yet).
    /// <paramref name="plannedEntities"/> are the indicators filed with it, added right after it's saved.
    /// </summary>
    Task<GateEvaluation> EvaluateNewAsync(IAppDbContext db, Domain.Entities.Case unsaved, StageGateTrigger trigger,
        int plannedEntities = 0, IReadOnlyList<EntityDisposition>? plannedDispositions = null, CancellationToken ct = default);
}

public sealed class StageGateEvaluator : IStageGateEvaluator
{
    // INV-43: the live notification-deadline settings, for the NotificationsRecorded fact. Optional so a gate
    // evaluated without them (tests, the feature off) treats no clock as running.
    private readonly Compliance.INotificationDeadlineSettingsProvider? _deadlines;

    public StageGateEvaluator(Compliance.INotificationDeadlineSettingsProvider? deadlines = null) => _deadlines = deadlines;

    /// <param name="summaryProvided">HR-01: the transition itself records a summary (the closing brief), so the
    /// "summary recorded" check is met by it.</param>
    public async Task<GateEvaluation> EvaluateAsync(IAppDbContext db, Guid caseId, StageGateTrigger trigger,
        bool summaryProvided = false, CancellationToken ct = default)
    {
        var gate = await db.StageGates.AsNoTracking()
            .Include(g => g.Requirements)
            .Where(g => g.IsActive && g.Trigger == trigger)
            .OrderBy(g => g.Name)   // BUG-237: one active gate per transition is enforced; if two slip in, pick the same one every time
            .FirstOrDefaultAsync(ct);

        // A gate is "in force" when it has requirements or requires commentary — a commentary-only gate
        // still gates the transition.
        if (gate is null || (gate.Requirements.Count == 0 && gate.CommentaryMinLength == 0))
            return GateEvaluation.None(trigger);

        var facts = await BuildFactsAsync(db, caseId, ct);
        if (summaryProvided) facts = facts with { HasSummary = true };
        return Judge(gate, trigger, facts);
    }

    public async Task<GateEvaluation> EvaluateNewAsync(IAppDbContext db, Domain.Entities.Case c, StageGateTrigger trigger,
        int plannedEntities = 0, IReadOnlyList<EntityDisposition>? plannedDispositions = null, CancellationToken ct = default)
    {
        var gate = await db.StageGates.AsNoTracking()
            .Include(g => g.Requirements)
            .Where(g => g.IsActive && g.Trigger == trigger)
            .OrderBy(g => g.Name)
            .FirstOrDefaultAsync(ct);
        if (gate is null || (gate.Requirements.Count == 0 && gate.CommentaryMinLength == 0))
            return GateEvaluation.None(trigger);

        var entities = c.Entities.Count + plannedEntities;
        // WF-16: the planned indicators' own verdicts (an import's), not all Unknown.
        var planned = plannedDispositions ?? [];
        var plannedMalicious = planned.Count(d => d == EntityDisposition.Malicious);
        var plannedJudged = planned.Count(d => d != EntityDisposition.Unknown);
        var facts = new GateCaseFacts(
            HasSummary: !string.IsNullOrWhiteSpace(c.Summary),
            HasAffectedCount: c.AffectedIndividualsCount is not null,
            HasDataElements: c.DataElements.Count > 0,
            HasAffectedStates: !string.IsNullOrWhiteSpace(c.AffectedStates),
            HasDetectionCaseId: !string.IsNullOrWhiteSpace(c.DetectionCaseId),
            EntityCount: entities,
            MaliciousEntityCount: c.Entities.Count(e => e.Disposition == EntityDisposition.Malicious) + plannedMalicious,
            EvidenceCount: 0,
            ReportCount: 0,
            HasIncidentCommander: !string.IsNullOrWhiteSpace(c.IncidentCommander),
            AffectedIndividualsCount: c.AffectedIndividualsCount ?? 0,
            Classification: c.Classification,
            UnknownEntityCount: entities - c.Entities.Count(e => e.Disposition != EntityDisposition.Unknown) - plannedJudged);
        return Judge(gate, trigger, facts);
    }

    private static GateEvaluation Judge(Domain.Entities.StageGate gate, StageGateTrigger trigger, GateCaseFacts facts)
    {
        var results = gate.Requirements
            .OrderBy(r => r.Order)
            .Select(r => new GateRequirementResult(
                r.Id, r.Order, r.Kind, r.CheckKey, r.Label, r.IsBlocking,
                MachineSatisfied: r.Kind == GateRequirementKind.MachineCheck
                    && GateCheckRegistry.IsSatisfied(r.CheckKey, facts, r.CheckParam), r.CheckParam))
            .ToList();

        return new GateEvaluation(true, trigger, gate.Name, results, gate.CommentaryMinLength, facts);
    }

    private async Task<GateCaseFacts> BuildFactsAsync(IAppDbContext db, Guid caseId, CancellationToken ct)
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
                HasIncidentCommander = x.IncidentCommander != null && x.IncidentCommander != "",
                x.Classification,
                MaterialityDetermined = x.Materiality.Status == MaterialityStatus.Material
                                        || x.Materiality.Status == MaterialityStatus.NotMaterial,
                x.DetectedAtUtc,
                x.ReportedAtUtc,
                MatStatus = x.Materiality.Status,
                MatDecidedOn = x.Materiality.DecidedOnUtc,
                MatRecordedAt = x.Materiality.RecordedAtUtc
            })
            .FirstOrDefaultAsync(ct);

        if (c is null)
            return new GateCaseFacts(false, false, false, false, false, 0, 0, 0, 0, false);

        var entityCount = await db.CaseEntities.CountAsync(e => e.CaseId == caseId, ct);
        var maliciousCount = await db.CaseEntities
            .CountAsync(e => e.CaseId == caseId && e.Disposition == EntityDisposition.Malicious, ct);
        var evidenceCount = await db.Evidence.CountAsync(e => e.CaseId == caseId, ct);
        // HR-12: the facts shown beside the attestations.
        var noCustody = await db.Evidence.CountAsync(e => e.CaseId == caseId && !e.CustodyEvents.Any(), ct);
        var unknown = await db.CaseEntities
            .CountAsync(e => e.CaseId == caseId && e.Disposition == EntityDisposition.Unknown, ct);
        // Only case reports count: the separate lessons-learned report is not the examiner-facing record.
        var reportCount = await db.Reports.CountAsync(r => r.CaseId == caseId && r.Kind == ReportKind.Case, ct);

        // E-26/PROD-41: what happened is recorded, and the follow-up question answered — actions logged or "none identified".
        var review = await db.PostIncidentReviews.AsNoTracking()
            .Where(r => r.CaseId == caseId)
            .Select(r => new { r.WhatHappened, r.NoActionsIdentified, At = r.ModifiedAtUtc ?? r.CreatedAtUtc })
            .FirstOrDefaultAsync(ct);
        var actions = await db.ImprovementActions.CountAsync(a => a.CaseId == caseId, ct);
        var reviewRecorded = review is not null && !string.IsNullOrWhiteSpace(review.WhatHappened);
        var lessonsCaptured = reviewRecorded && (review!.NoActionsIdentified || actions > 0);

        // INV-13: tasks still open (not done or cancelled).
        var openTasks = await db.ActionItems.CountAsync(a => a.CaseId == caseId
            && a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled, ct);

        // INV-43: a notification clock is running and no report time is recorded — the same trigger and
        // jurisdiction test as the on-case countdown (NotificationDeadlineService), without the windows. BUG-625: the
        // jurisdictions in play by the same rule as every other view (what was kept when it was reported), not today's
        // mapping of every element, which closed a case with a kept regulator still owed and blocked one owing none.
        var notificationPending = false;
        if (_deadlines?.Current is { Enabled: true } nd && c.ReportedAtUtc is null
            && Compliance.NotificationDeadlineService.ResolveStart(nd.StartBasis, c.Classification, c.DetectedAtUtc,
                c.MatStatus, c.MatDecidedOn, c.MatRecordedAt) is not null)
        {
            notificationPending = await Compliance.NotificationDeadlineService.AnyUnnotifiedAsync(db, caseId, ct);
        }

        return new GateCaseFacts(
            c.HasSummary, c.HasAffectedCount, c.HasDataElements, c.HasAffectedStates, c.HasDetectionCaseId,
            entityCount, maliciousCount, evidenceCount, reportCount, c.HasIncidentCommander,
            c.AffectedIndividualsCount, c.Classification, c.MaterialityDetermined, lessonsCaptured, openTasks,
            notificationPending, unknown, noCustody, reviewRecorded ? review!.At : null, actions,
            review?.NoActionsIdentified ?? false);
    }
}
