using IncidentManager.Domain.Enums;
using IncidentManager.Application.Common;

namespace IncidentManager.Application.StageGates;

/// <summary>
/// Thrown when a gated transition is attempted with blocking requirements unmet and no override
/// justification supplied. Carries the unmet requirements so the caller can surface them.
/// </summary>
public sealed class GateNotSatisfiedException : Exception
{
    public StageGateTrigger Trigger { get; }
    public string? GateName { get; }
    public IReadOnlyList<GateRequirementResult> Unmet { get; }

    public GateNotSatisfiedException(StageGateTrigger trigger, string? gateName,
        IReadOnlyList<GateRequirementResult> unmet)
        : base($"Stage gate '{gateName}' is not satisfied: {Plural.Of(unmet.Count, "required item")} outstanding. " +
               "Complete them or override with a recorded justification.")
    {
        Trigger = trigger;
        GateName = gateName;
        Unmet = unmet;
    }
}

/// <summary>Maps a target classification / lifecycle action to the gate trigger that governs it.</summary>
public static class StageGateTriggers
{
    /// <summary>The gate that governs escalating/promoting to <paramref name="to"/>, if any.</summary>
    public static StageGateTrigger? ForClassification(Classification to) => to switch
    {
        Classification.AdverseEvent => StageGateTrigger.PromoteToAdverseEvent,
        Classification.Incident => StageGateTrigger.EscalateToIncident,
        Classification.Breach => StageGateTrigger.EscalateToBreach,
        _ => null
    };

    /// <summary>
    /// BUG-60/61: the gate of every rung climbed from <paramref name="from"/> (null: intake, or a case being created) up
    /// to <paramref name="to"/>, lowest first. Adverse Event straight to Breach passes the Incident gate on the way.
    /// </summary>
    public static IReadOnlyList<StageGateTrigger> Climb(Classification? from, Classification to) =>
        Enum.GetValues<Classification>()
            .Where(r => (from is null || r > from) && r <= to)
            .Select(ForClassification).Where(t => t is not null).Select(t => t!.Value)
            .ToList();

    public static string Label(StageGateTrigger t) => t switch
    {
        StageGateTrigger.PromoteToAdverseEvent => "Promote to Adverse Event",
        StageGateTrigger.EscalateToIncident => "Escalate to Incident",
        StageGateTrigger.EscalateToBreach => "Escalate to Breach",
        StageGateTrigger.CloseCase => "Close case",
        _ => t.ToString()
    };
}
