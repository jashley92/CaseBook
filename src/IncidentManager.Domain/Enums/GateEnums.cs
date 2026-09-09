namespace IncidentManager.Domain.Enums;

/// <summary>
/// Which case transition a stage gate governs, identified by its <b>target</b> state/action — the
/// completeness bar for "becoming a Breach" is the same regardless of where the case came from.
/// Covers the promotions/escalations up the classification ladder plus case closure (a phase change).
/// </summary>
public enum StageGateTrigger
{
    /// <summary>Complex Event (intake) → formal Adverse Event.</summary>
    PromoteToAdverseEvent = 0,
    EscalateToIncident = 1,
    EscalateToBreach = 2,
    /// <summary>Advancing the lifecycle phase to Closed.</summary>
    CloseCase = 3
}

/// <summary>How a single gate requirement is satisfied.</summary>
public enum GateRequirementKind
{
    /// <summary>Automatically evaluated against the case's data (a whitelisted fact check).</summary>
    MachineCheck = 0,

    /// <summary>An affirmation the analyst must consciously make at the moment of the transition.</summary>
    Attestation = 1
}

// The machine checks a requirement can evaluate are no longer a closed enum. As of X-06 (b) stage 1 they
// live in a code-defined predicate registry (Application: GateCheckRegistry / GateCheckKeys) keyed by a
// stable string, so the reviewed set is open for additive extension while every predicate stays code. A
// requirement stores its selected check as StageGateRequirement.CheckKey (the registry key).
