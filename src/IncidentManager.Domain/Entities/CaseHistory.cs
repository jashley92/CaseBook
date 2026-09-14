using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>Immutable record of a classification transition (AdverseEvent -> Incident -> Breach).</summary>
public class ClassificationChange : Entity
{
    public Guid CaseId { get; set; }

    /// <summary>Null for the initial classification when the case was opened.</summary>
    public Classification? From { get; set; }
    public Classification To { get; set; }
    public string Reason { get; set; } = string.Empty;
    public string ChangedBy { get; set; } = string.Empty;
    public DateTimeOffset ChangedAtUtc { get; set; }
}

/// <summary>Immutable record of a lifecycle-phase transition.</summary>
public class StatusChange : Entity
{
    public Guid CaseId { get; set; }
    public CasePhase? From { get; set; }
    public CasePhase To { get; set; }
    public string? Reason { get; set; }
    public string ChangedBy { get; set; } = string.Empty;
    public DateTimeOffset ChangedAtUtc { get; set; }
}

/// <summary>Immutable record of a materiality-determination transition (Undetermined → Under review →
/// Material / Not material). Carries the off-app decision-maker/date/rationale as recorded at the time.</summary>
public class MaterialityChange : Entity
{
    public Guid CaseId { get; set; }

    /// <summary>The prior status (Undetermined for the first determination).</summary>
    public MaterialityStatus From { get; set; }
    public MaterialityStatus To { get; set; }
    public string? DecisionMaker { get; set; }
    public DateTimeOffset? DecidedOnUtc { get; set; }
    public string? Rationale { get; set; }
    public string ChangedBy { get; set; } = string.Empty;
    public DateTimeOffset ChangedAtUtc { get; set; }
}

/// <summary>Immutable record of a severity change.</summary>
public class SeverityChange : Entity
{
    public Guid CaseId { get; set; }

    /// <summary>Null for the initial severity when the case was opened.</summary>
    public Severity? From { get; set; }
    public Severity To { get; set; }
    public string? Reason { get; set; }
    public string ChangedBy { get; set; } = string.Empty;
    public DateTimeOffset ChangedAtUtc { get; set; }
}
