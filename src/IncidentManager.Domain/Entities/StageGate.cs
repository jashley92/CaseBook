using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A completeness gate an admin defines for one case transition (C-07). Before a case can be promoted
/// onto the ladder, escalated to Incident/Breach, or closed, the active gate for that transition is
/// evaluated: its <see cref="StageGateRequirement"/>s must be satisfied — or the transition must be
/// consciously overridden with a recorded justification. Gates are admin reference data — audited and
/// hash-chained like <see cref="CaseTemplate"/>, but not case-scoped. Generalises the fixed C-04
/// breach-readiness idea into an admin-authored gate per transition.
/// </summary>
public class StageGate : AuditableEntity, IHashableEntity
{
    /// <summary>The transition this gate governs. At most one <see cref="IsActive"/> gate per trigger.</summary>
    public StageGateTrigger Trigger { get; set; }

    /// <summary>Inactive gates are retained (for audit/history) but not enforced or shown.</summary>
    public bool IsActive { get; set; } = true;

    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>Minimum length of the analyst commentary required to pass this gate (0 = commentary is
    /// optional). When &gt; 0 the transition demands a note of at least this many characters, recorded on
    /// the <see cref="GatePassage"/> — a deliberate, defensible record of the analyst's reasoning.</summary>
    public int CommentaryMinLength { get; set; }

    /// <summary>The ordered requirements evaluated for this transition.</summary>
    public List<StageGateRequirement> Requirements { get; set; } = [];

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        (int)Trigger, IsActive, Name, Description, CommentaryMinLength, CreatedBy, CreatedAtUtc.ToString("o"));
}

/// <summary>
/// One requirement within a <see cref="StageGate"/>. Either a machine check (a
/// <see cref="CheckKey"/> into the code-defined predicate registry) evaluated automatically against the
/// case's data, or an <see cref="GateRequirementKind.Attestation"/> the analyst must consciously confirm
/// at the transition. Blocking requirements stop the transition until satisfied (or overridden);
/// non-blocking ones are advisory — shown, but not enforced.
/// </summary>
public class StageGateRequirement : Entity, IHashableEntity
{
    public Guid GateId { get; set; }

    /// <summary>Position within the gate (ascending).</summary>
    public int Order { get; set; }

    public GateRequirementKind Kind { get; set; }

    /// <summary>The registry key of the machine check to evaluate; set only when <see cref="Kind"/> is
    /// MachineCheck. A stable string (e.g. "SummaryPresent") so the set of checks is additive and the
    /// value travels verbatim in a config bundle.</summary>
    public string? CheckKey { get; set; }

    /// <summary>The threshold for a <b>parameterized</b> machine check (e.g. "at least N entities");
    /// null for a parameterless check or an attestation. The predicate family is code; this value is
    /// admin data (X-06 (b) stage 2).</summary>
    public int? CheckParam { get; set; }

    /// <summary>Display text: the attestation wording, or a label for the machine check.</summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>When true, an unmet requirement blocks the transition unless overridden.</summary>
    public bool IsBlocking { get; set; } = true;

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        GateId, Order, (int)Kind, CheckKey ?? "", CheckParam?.ToString() ?? "", Label, IsBlocking);
}

/// <summary>
/// A tamper-evident record that a case passed (or was forced through) a stage gate, written on the
/// case at the moment of the transition. Captures who passed it, whether it was overridden and why,
/// and a snapshot of each requirement's outcome — the examiner-facing evidence that the regulatory
/// artifact was complete (or that its incompleteness was deliberate and justified).
/// </summary>
public class GatePassage : Entity, IHashableEntity
{
    public Guid CaseId { get; set; }
    public StageGateTrigger Trigger { get; set; }
    public DateTimeOffset PassedAtUtc { get; set; }
    public string PassedBy { get; set; } = string.Empty;

    /// <summary>True when blocking requirements were unmet but the transition was forced through anyway.</summary>
    public bool WasOverridden { get; set; }
    public string? OverrideJustification { get; set; }

    /// <summary>Analyst commentary recorded at the transition (a gate may require a minimum length). Null
    /// when none was provided and the gate did not require it.</summary>
    public string? Commentary { get; set; }

    /// <summary>Human-readable snapshot of each requirement and its outcome at transition time.</summary>
    public string Detail { get; set; } = string.Empty;

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, (int)Trigger, PassedAtUtc.ToString("o"), PassedBy, WasOverridden, OverrideJustification, Commentary, Detail);
}
