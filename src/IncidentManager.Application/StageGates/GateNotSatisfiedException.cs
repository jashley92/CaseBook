using IncidentManager.Domain.Enums;

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
        : base($"Stage gate '{gateName}' is not satisfied: {unmet.Count} required item(s) outstanding. " +
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

    public static string Label(StageGateTrigger t) => t switch
    {
        StageGateTrigger.PromoteToAdverseEvent => "Promote to Adverse Event",
        StageGateTrigger.EscalateToIncident => "Escalate to Incident",
        StageGateTrigger.EscalateToBreach => "Escalate to Breach",
        StageGateTrigger.CloseCase => "Close case",
        _ => t.ToString()
    };
}
