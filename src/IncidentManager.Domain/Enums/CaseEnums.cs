namespace IncidentManager.Domain.Enums;

/// <summary>
/// The three formal IRP classifications, in ascending order of severity/consequence.
/// Escalation moves upward (AdverseEvent -> Incident -> Breach).
/// </summary>
public enum Classification
{
    AdverseEvent = 1,
    Incident = 2,
    Breach = 3
}

/// <summary>Investigation lifecycle phases, aligned to NIST SP 800-61.</summary>
public enum CasePhase
{
    New = 0,
    Triage = 1,
    Containment = 2,
    Eradication = 3,
    Recovery = 4,
    PostIncident = 5,
    Closed = 6
}

/// <summary>Analyst-assessed severity of the item.</summary>
public enum Severity
{
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>Where the item originated.</summary>
public enum CaseOrigin
{
    /// <summary>Detected by our own tooling/analysts (e.g., SIEM).</summary>
    InternalDetection = 0,

    /// <summary>A third-party/vendor event we are managing (e.g., a vendor data breach).</summary>
    ThirdParty = 1
}
