using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Web.Components.Pages.Workspace;

/// <summary>
/// RD-27 (lifted out of CaseWorkspace): the action dialog that's open and what's been entered in it. The workspace keeps
/// one for the life of the page, so text typed into a dialog that was cancelled is still there when it's reopened, as
/// before; opening a dialog resets only what it always reset. <see cref="Name"/> is null when no dialog is open.
/// </summary>
public sealed class CaseActionDraft
{
    /// <summary>reclass, severity, status, handoff, legal, materiality, supersede, restrict, unrestrict, holdrelease,
    /// archive, reopen or assign.</summary>
    public string? Name { get; set; }
    public string? Error { get; set; }

    /// <summary>RD-15: promoting, reclassifying and changing severity or phase are a sheet under the header, not a modal.</summary>
    public bool IsSheet => Name is "reclass" or "severity" or "status";

    public TransitionDraft Transition { get; } = new();

    // Reclassify, severity, phase, reopen
    public Classification NewClass { get; set; } = Classification.Incident;
    public string ReclassReason { get; set; } = "";
    public CasePhase NewPhase { get; set; } = CasePhase.Triage;
    public string? PhaseReason { get; set; }
    public Severity NewSeverity { get; set; } = Severity.Medium;
    public string? SeverityReason { get; set; }
    public string? ReopenReason { get; set; }

    // Assign
    public string AssignUserId { get; set; } = "";
    public CaseAssignmentRole AssignRole { get; set; } = CaseAssignmentRole.Analyst;

    // Legal referral, legal hold, materiality (REL-02: the baselines catch a concurrent edit)
    public string? LegalContact { get; set; }
    public string? LegalNote { get; set; }
    public string? LegalBaseline { get; set; }
    public string? HoldReleaseReason { get; set; }   // F-12
    public MaterialityStatus MaterialityStatus { get; set; } = MaterialityStatus.UnderReview;
    public string? MaterialityDecisionMaker { get; set; }
    public DateTime? MaterialityDecidedOn { get; set; }
    public string? MaterialityRationale { get; set; }
    public string? MaterialityBaseline { get; set; }

    /// <summary>Whether the materiality picker's selection is a final call (it needs full provenance).</summary>
    public bool MaterialityIsFinal => MaterialityStatus is MaterialityStatus.Material or MaterialityStatus.NotMaterial;

    // S-08: need-to-know restriction
    public string? RestrictReason { get; set; }
    public string ClearanceNote { get; set; } = "";

    // PROD-11: supersede as a duplicate
    public Guid? SupersedeTargetId { get; set; }
    public string? SupersedeTargetNumber { get; set; }
    public string? SupersedeQuery { get; set; }
    public string? SupersedeReason { get; set; }
    public bool SupersedeCopy { get; set; } = true;
    public IReadOnlyList<LinkableCase> SupersedeResults { get; set; } = [];
    public IReadOnlyList<CaseLinkView> SupersedeLinked { get; set; } = [];

    // INV-15: structured handoff
    public string? HandoffTo { get; set; }
    public string? HandoffState { get; set; }
    public string? HandoffDone { get; set; }
    public string? HandoffOpen { get; set; }
    public string? HandoffWatch { get; set; }
    public bool HandoffEmail { get; set; } = true;
    public bool HandoffTasks { get; set; } = true;
    public IReadOnlyList<UserSummary> HandoffPeople { get; set; } = [];
}
