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

    /// <summary>BUG-448: counts each opening of a dialog, so a save that finishes after its dialog was closed or replaced
    /// can tell, and leaves the one open now (and its text) alone.</summary>
    public int Opening { get; private set; }

    public void Open(string name)
    {
        Name = name;
        Opening++;
    }

    /// <summary>RD-15: promoting, reclassifying and changing severity or phase are a sheet under the header, not a modal.</summary>
    public bool IsSheet => Name is "reclass" or "severity" or "status";

    public TransitionDraft Transition { get; } = new();

    // Reclassify, severity, phase, reopen
    public Classification NewClass { get; set; } = Classification.Incident;
    public string ReclassReason { get; set; } = "";
    public CasePhase NewPhase { get; set; } = CasePhase.Triage;
    public string? PhaseReason { get; set; }
    /// <summary>BUG-165: going past Containment without it: true = it was contained (at <see cref="ContainedAt"/>, a wall
    /// time in the display zone), false = it wasn't needed (<see cref="ContainmentNotNeededReason"/>), null = not said.</summary>
    public bool? WasContained { get; set; }
    public DateTime? ContainedAt { get; set; }
    public string? ContainmentNotNeededReason { get; set; }

    /// <summary>BUG-208: going past Recovery without it, when it was resolved (a wall time in the display zone).</summary>
    public DateTime? ResolvedAt { get; set; }
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
    /// <summary>BUG-07: when the decision was made, as a wall time in the display zone (a datetime-local input).</summary>
    public DateTime? MaterialityDecidedOn { get; set; }
    /// <summary>WF-14: the recorded decision instant the form was filled from; kept as it is when the time isn't changed.</summary>
    public DateTimeOffset? MaterialityDecidedOnRecorded { get; set; }

    /// <summary>
    /// WF-14: the decision instant to save. A wall time in the repeated autumn hour names two instants and reads back as
    /// the later one, so re-saving the dialog (to fix the rationale, say) moved a 01:30 EDT decision to 01:30 EST, an hour
    /// later. The recorded instant is kept when the time shown for it wasn't changed.
    /// </summary>
    public DateTimeOffset? DecidedOnUtc(TimeZoneInfo zone)
    {
        if (!MaterialityIsFinal || MaterialityDecidedOn is not { } wall) return null;
        if (MaterialityDecidedOnRecorded is { } kept)
        {
            var shown = WallClock.ToWall(kept, zone);
            if (shown.AddSeconds(-shown.Second).AddMilliseconds(-shown.Millisecond) == wall) return kept;
        }
        return WallClock.ToUtc(wall, zone);
    }
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
    /// <summary>BUG-129/160: what superseding would show to people who can't see the case it comes from; null when nothing.</summary>
    public IncidentManager.Application.Cases.CaseService.SupersedeExposure? SupersedeExposure { get; set; }
    public bool SupersedeAck { get; set; }
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

/// <summary>BUG-337: the case an action dialog or the close-out acted on. A case switch removes the form while it saves,
/// so the workspace, not the form, decides whether the follow-up (a reload, the close-out, a demotion) still applies.</summary>
public readonly record struct CaseActionFor(Guid CaseId, string Number)
{
    /// <summary>Whether it was for the case the workspace has open now.</summary>
    public bool IsFor(Guid openCaseId) => CaseId == openCaseId;
}

/// <summary>An action dialog applied (BUG-337): the case it was for, what to say, and for a supersede, the reason to
/// close it with. <paramref name="Opening"/> (BUG-448): the dialog's <see cref="CaseActionDraft.Opening"/> when it was
/// applied (0 from the close-out view).</summary>
public readonly record struct CaseActionApplied(Guid CaseId, string Number, string Done, string? CloseReason, int Opening = 0)
{
    public bool IsFor(Guid openCaseId) => CaseId == openCaseId;

    /// <summary>What to say once the workspace has moved to another case: only that it was done, and on which case.</summary>
    public string ElsewhereMessage => ElsewhereText(Number, Done);

    public static string ElsewhereText(string number, string done) =>
        string.IsNullOrEmpty(done) ? $"Saved on {number}." : $"{number}: {done.TrimEnd('.')}.";
}
