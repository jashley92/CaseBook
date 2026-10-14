using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>Immutable record of a classification transition (AdverseEvent -> Incident -> Breach). BUG-70: hashed and in
/// the record check, like the rest of the case record, so a direct edit of when it happened is caught.</summary>
public class ClassificationChange : Entity, IHashableEntity
{
    public Guid CaseId { get; set; }

    /// <summary>Null for the initial classification when the case was opened.</summary>
    public Classification? From { get; set; }
    public Classification To { get; set; }
    public string Reason { get; set; } = string.Empty;
    public string ChangedBy { get; set; } = string.Empty;
    public DateTimeOffset ChangedAtUtc { get; set; }

    /// <summary>INV-05: when the change actually happened, if the analyst recorded it after the fact; null means
    /// it happened when it was recorded (<see cref="ChangedAtUtc"/>, which never changes).</summary>
    public DateTimeOffset? EffectiveAtUtc { get; set; }

    /// <summary>When the change happened: the effective time if one was given, else the recorded time.</summary>
    public DateTimeOffset EffectiveAt => EffectiveAtUtc ?? ChangedAtUtc;

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|', CaseId, Canonical.Num(From), Canonical.Num(To), Canonical.Text(Reason),
        ChangedBy, Canonical.Time(ChangedAtUtc), Canonical.Time(EffectiveAtUtc));
}

/// <summary>Immutable record of a lifecycle-phase transition. BUG-70: hashed (its effective time moves the clocks).</summary>
public class StatusChange : Entity, IHashableEntity
{
    public Guid CaseId { get; set; }
    public CasePhase? From { get; set; }
    public CasePhase To { get; set; }
    public string? Reason { get; set; }
    public string ChangedBy { get; set; } = string.Empty;
    public DateTimeOffset ChangedAtUtc { get; set; }

    /// <summary>INV-05: when the change actually happened, if the analyst recorded it after the fact; null means
    /// it happened when it was recorded (<see cref="ChangedAtUtc"/>, which never changes).</summary>
    public DateTimeOffset? EffectiveAtUtc { get; set; }

    /// <summary>When the change happened: the effective time if one was given, else the recorded time.</summary>
    public DateTimeOffset EffectiveAt => EffectiveAtUtc ?? ChangedAtUtc;

    /// <summary>HR-01: on a change to Closed, the outcome the case was closed with (a <see cref="CaseOutcome"/> key).</summary>
    public string? OutcomeKey { get; set; }

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|', CaseId, Canonical.Num(From), Canonical.Num(To), Canonical.Text(Reason),
        ChangedBy, Canonical.Time(ChangedAtUtc), Canonical.Time(EffectiveAtUtc), OutcomeKey);
}

/// <summary>Immutable record of a materiality-determination transition (Undetermined → Under review →
/// Material / Not material). Carries the off-app decision-maker/date/rationale as recorded at the time.</summary>
public class MaterialityChange : Entity, IHashableEntity
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

    public string? RowHash { get; set; }   // BUG-70

    public string BuildCanonicalContent() => string.Join('|', CaseId, Canonical.Num(From), Canonical.Num(To), Canonical.Text(DecisionMaker),
        Canonical.Time(DecidedOnUtc), Canonical.Text(Rationale), ChangedBy, Canonical.Time(ChangedAtUtc));
}

/// <summary>
/// INV-31: immutable record of a change to who is on a case — someone assigned, their role changed (including taking
/// or handing over command), or removed — so "who was in charge at T+26h" is answered by the timeline, not the audit.
/// </summary>
public class AssignmentChange : Entity, IHashableEntity
{
    public Guid CaseId { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string UserDisplayName { get; set; } = string.Empty;
    /// <summary>The role before the change; null when the person was newly assigned.</summary>
    public CaseAssignmentRole? From { get; set; }
    /// <summary>The role after the change; null when the person was removed from the case.</summary>
    public CaseAssignmentRole? To { get; set; }
    public string ChangedBy { get; set; } = string.Empty;
    public DateTimeOffset ChangedAtUtc { get; set; }

    public string? RowHash { get; set; }   // BUG-70

    public string BuildCanonicalContent() => string.Join('|', CaseId, UserId, Canonical.Text(UserDisplayName), Canonical.Num(From),
        Canonical.Num(To), ChangedBy, Canonical.Time(ChangedAtUtc));
}

/// <summary>
/// HR-05: immutable record of a change to an entity's verdict on a case (e.g. Unknown → Compromised), with why. The
/// findings history: when the team reached each conclusion about an account, host or indicator, who, and on what basis.
/// Written when an existing entity is re-assessed, not when one is first added with a verdict.
/// </summary>
public class EntityVerdictChange : Entity, IHashableEntity
{
    public Guid CaseId { get; set; }
    public Guid EntityId { get; set; }
    /// <summary>How the entity read at the time (its label, else its value), so the history reads the same if it's later removed.</summary>
    public string EntityLabel { get; set; } = string.Empty;
    public EntityDisposition From { get; set; }
    public EntityDisposition To { get; set; }
    public string? Reason { get; set; }
    public string ChangedBy { get; set; } = string.Empty;
    public DateTimeOffset ChangedAtUtc { get; set; }

    /// <summary>BUG-414: when the verdict was actually reached, if that was before it was recorded; null means it was
    /// reached when it was recorded (<see cref="ChangedAtUtc"/>, which never changes). Corrected later through a
    /// <see cref="TransitionTimeCorrection"/>, as a phase change is.</summary>
    public DateTimeOffset? EffectiveAtUtc { get; set; }

    /// <summary>When the verdict was reached: the effective time if one was given, else the recorded time.</summary>
    public DateTimeOffset EffectiveAt => EffectiveAtUtc ?? ChangedAtUtc;

    public string? RowHash { get; set; }   // BUG-70

    // BUG-414: the effective time is folded in only when there is one, so earlier rows keep their exact canonical.
    public string BuildCanonicalContent()
    {
        var content = string.Join('|', CaseId, EntityId, Canonical.Text(EntityLabel), Canonical.Num(From),
            Canonical.Num(To), Canonical.Text(Reason), ChangedBy, Canonical.Time(ChangedAtUtc));
        return EffectiveAtUtc is { } at ? string.Join('|', content, "eff", Canonical.Time(at)) : content;
    }
}

/// <summary>Immutable record of a severity change. BUG-70: hashed.</summary>
public class SeverityChange : Entity, IHashableEntity
{
    public Guid CaseId { get; set; }

    /// <summary>Null for the initial severity when the case was opened.</summary>
    public Severity? From { get; set; }
    public Severity To { get; set; }
    public string? Reason { get; set; }
    public string ChangedBy { get; set; } = string.Empty;
    public DateTimeOffset ChangedAtUtc { get; set; }

    /// <summary>INV-05: when the change actually happened, if the analyst recorded it after the fact; null means
    /// it happened when it was recorded (<see cref="ChangedAtUtc"/>, which never changes).</summary>
    public DateTimeOffset? EffectiveAtUtc { get; set; }

    /// <summary>When the change happened: the effective time if one was given, else the recorded time.</summary>
    public DateTimeOffset EffectiveAt => EffectiveAtUtc ?? ChangedAtUtc;

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|', CaseId, Canonical.Num(From), Canonical.Num(To), Canonical.Text(Reason),
        ChangedBy, Canonical.Time(ChangedAtUtc), Canonical.Time(EffectiveAtUtc));
}
