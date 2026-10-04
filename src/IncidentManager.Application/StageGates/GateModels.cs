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
    int AffectedIndividualsCount = 0,
    Classification? Classification = null,
    bool MaterialityDetermined = false,
    bool LessonsCaptured = false,
    int OpenTaskCount = 0,
    bool NotificationPending = false,
    // HR-12: what an attestation is about, shown beside it so it isn't ticked blind, and the Unknown-verdict check.
    int UnknownEntityCount = 0,
    int EvidenceWithoutCustody = 0,
    DateTimeOffset? ReviewRecordedAtUtc = null,
    int ImprovementActionCount = 0,
    bool NoActionsIdentified = false);

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
    int CommentaryMinLength = 0,
    GateCaseFacts? Facts = null)
{
    /// <summary>HR-12: the facts to show beside a requirement (an attestation's evidence or review, a count), if any.</summary>
    public string? FactFor(GateRequirementResult r, Func<DateTimeOffset, string>? date = null) =>
        Facts is null ? null : GateFacts.For(r, Facts, date);

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

/// <summary>
/// HR-12: the record's facts behind a requirement, so an attestation like "Evidence preserved and chain of custody
/// complete" is ticked against "1 evidence file · custody log on each", not blind. An attestation is matched to its
/// facts by what it's about (its wording names evidence or custody, or a post-incident review or lessons); one about
/// something else shows nothing.
/// </summary>
public static class GateFacts
{
    public static string? For(GateRequirementResult r, GateCaseFacts f, Func<DateTimeOffset, string>? date = null)
    {
        date ??= d => d.UtcDateTime.ToString("d MMM yyyy", System.Globalization.CultureInfo.InvariantCulture);
        if (r.Kind == GateRequirementKind.MachineCheck)
            return r.CheckKey == GateCheckKeys.EntitiesAssessed && f.UnknownEntityCount > 0
                ? $"{f.UnknownEntityCount} still Unknown" : null;
        var label = r.Label.ToLowerInvariant();
        if (label.Contains("evidence") || label.Contains("custody")) return Evidence(f);
        if (new[] { "post-incident", "post incident", "lessons", "after-action", "retrospective" }.Any(label.Contains))
            return Review(f, date);
        return null;
    }

    private static string Evidence(GateCaseFacts f) => f.EvidenceCount switch
    {
        0 => "No evidence files attached",
        var n => $"{n} evidence {(n == 1 ? "file" : "files")} · " + (f.EvidenceWithoutCustody == 0
            ? (n == 1 ? "custody log on it" : "custody log on each")
            : $"{f.EvidenceWithoutCustody} without a custody log")
    };

    private static string Review(GateCaseFacts f, Func<DateTimeOffset, string> date) => f.ReviewRecordedAtUtc is not { } at
        ? "No post-incident review recorded"
        : $"Review recorded {date(at)} · " + (f.ImprovementActionCount > 0
            ? $"{f.ImprovementActionCount} improvement {(f.ImprovementActionCount == 1 ? "action" : "actions")}"
            : f.NoActionsIdentified ? "no actions identified" : "follow-up actions not yet answered");
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
            // HR-12: what was in front of the analyst when they attested.
            return eval.FactFor(r) is { } fact ? $"[{status}] {r.Label} ({kind}; shown: {fact})" : $"[{status}] {r.Label} ({kind})";
        });
        sb.Append(string.Join("; ", parts));
        return sb.ToString();
    }
}
