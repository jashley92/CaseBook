using System.Text;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.StageGates;

/// <summary>
/// A snapshot of the machine-checkable facts about a case, decoupled from EF so the check predicates in
/// <see cref="GateCheckRegistry"/> stay pure and unit-testable.
/// </summary>
public sealed record GateCaseFacts(
    bool HasSummary,
    bool HasAffectedCount,
    bool HasDataElements,
    bool HasAffectedStates,
    bool HasDetectionCaseId,
    int EntityCount,
    int MaliciousEntityCount,
    int EvidenceCount,
    int ReportCount,
    bool HasIncidentCommander,
    int AffectedIndividualsCount = 0);

/// <summary>The outcome of one requirement against a specific case.</summary>
public sealed record GateRequirementResult(
    Guid RequirementId,
    int Order,
    GateRequirementKind Kind,
    string? CheckKey,
    string Label,
    bool IsBlocking,
    bool MachineSatisfied)
{
    /// <summary>
    /// Whether the requirement is satisfied. A machine check uses its computed result; an attestation is
    /// satisfied only by a runtime confirmation supplied in <paramref name="attestedIds"/> (never by
    /// stored data — the analyst must consciously affirm it at the transition).
    /// </summary>
    public bool IsSatisfiedBy(IReadOnlySet<Guid> attestedIds) =>
        Kind == GateRequirementKind.MachineCheck ? MachineSatisfied : attestedIds.Contains(RequirementId);
}

/// <summary>A case evaluated against the gate for one transition.</summary>
public sealed record GateEvaluation(
    bool GateExists,
    StageGateTrigger Trigger,
    string? GateName,
    IReadOnlyList<GateRequirementResult> Requirements,
    int CommentaryMinLength = 0)
{
    public static GateEvaluation None(StageGateTrigger t) =>
        new(false, t, null, Array.Empty<GateRequirementResult>());

    /// <summary>Whether passing this gate requires analyst commentary of a minimum length.</summary>
    public bool RequiresCommentary => CommentaryMinLength > 0;

    /// <summary>Blocking requirements not satisfied given the attestations supplied.</summary>
    public IReadOnlyList<GateRequirementResult> UnmetBlocking(IReadOnlySet<Guid> attestedIds) =>
        Requirements.Where(r => r.IsBlocking && !r.IsSatisfiedBy(attestedIds)).ToList();

    public bool IsSatisfiedBy(IReadOnlySet<Guid> attestedIds) => UnmetBlocking(attestedIds).Count == 0;

    /// <summary>Attestation requirements (the ones the analyst must tick at the transition).</summary>
    public IReadOnlyList<GateRequirementResult> Attestations =>
        Requirements.Where(r => r.Kind == GateRequirementKind.Attestation).ToList();
}

/// <summary>Builds the tamper-evident detail string stored on a <c>GatePassage</c>.</summary>
public static class GateDetail
{
    public static string Summarize(GateEvaluation eval, IReadOnlySet<Guid> attestedIds)
    {
        var sb = new StringBuilder();
        sb.Append("Gate '").Append(eval.GateName).Append("': ");
        var parts = eval.Requirements.OrderBy(r => r.Order).Select(r =>
        {
            var met = r.IsSatisfiedBy(attestedIds);
            var status = met ? "MET" : (r.IsBlocking ? "UNMET(OVERRIDDEN)" : "UNMET(advisory)");
            var kind = r.Kind == GateRequirementKind.Attestation ? "attest" : "check";
            return $"[{status}] {r.Label} ({kind})";
        });
        sb.Append(string.Join("; ", parts));
        return sb.ToString();
    }
}
