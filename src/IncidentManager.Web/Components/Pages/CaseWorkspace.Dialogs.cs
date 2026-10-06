using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Components.Pages.CaseTabs;
using IncidentManager.Web.Components.Pages.Workspace;
using IncidentManager.Web.Components.Shared;
using IncidentManager.Web.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Routing;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.JSInterop;

namespace IncidentManager.Web.Components.Pages;

/// <summary>
/// RD-27: opening the action dialogs and the close-out view, and what happens around them: the gate each transition
/// runs, the close-out draft, a stage gate's "Fix", the shared confirm and FR-05's leave guard. The dialogs themselves
/// are Workspace/CaseActionForm and Workspace/CaseCloseOut.
/// </summary>
public partial class CaseWorkspace
{
    private async Task OpenModal(string name)
    {
        if (_case is null) return;
        var a = _action;
        a.Name = name;
        a.Error = null;
        // Reclassifying is almost always an escalation, so the picker starts on the next rung up (the first rung
        // for a Complex Event); a Breach, the top, starts on itself. Picking a lower rung is still one change.
        a.NewClass = _case.Classification switch
        {
            null => Classification.AdverseEvent,
            Classification.AdverseEvent => Classification.Incident,
            Classification.Incident => Classification.Breach,
            var c => c.Value,
        };
        a.NewSeverity = _case.Severity;
        a.NewPhase = _case.Phase;
        a.Transition.Reset(WallClock.ToWall(Clock.UtcNow, TimeDisp.Zone));

        if (name == "holdrelease") a.HoldReleaseReason = null;   // don't carry a cancelled attempt's text over
        if (name == "handoff")
        {
            a.HandoffPeople = await Cases.MentionableAsync(Id);
            PrefillHandoff();
        }

        if (name is "restrict" or "unrestrict")
        {
            a.RestrictReason = null;
            var roles = await Cases.GetRestrictedClearanceRolesAsync();
            a.ClearanceNote = roles.Count > 0
                ? $"Only its incident commander, the people assigned to it and anyone with {Ui.RolePhrase(roles)} can open it."
                : "Only its incident commander and the people assigned to it can open it.";
        }

        if (name == "supersede")
        {
            a.SupersedeTargetId = null; a.SupersedeTargetNumber = null; a.SupersedeQuery = null; a.SupersedeReason = null;
            a.SupersedeCopy = true; a.SupersedeResults = [];
            // Cases already linked to this one are the likely "keep" candidates (a DuplicateOf link first).
            a.SupersedeLinked = (await Cases.GetCaseLinksAsync(Id))
                .OrderByDescending(l => l.Type == CaseLinkType.DuplicateOf && l.Outgoing).ToList();
        }

        // Open the assign form clean (a prior cancelled attempt may have left a stale selection).
        if (name == "assign") { a.AssignUserId = ""; a.AssignRole = CaseAssignmentRole.Analyst; }

        // REL-02: prefill the Legal-referral form from the current referral (edit-in-place) and capture the
        // optimistic-concurrency baseline, so a concurrent referral edit isn't silently overwritten.
        if (name == "legal")
        {
            a.LegalContact = _case.LegalReferral.ReferredToContact;
            a.LegalNote = _case.LegalReferral.RegulatoryRelevanceNote;
            a.LegalBaseline = _case.LegalReferralConcurrencyStamp();
        }

        // Prefill the materiality form from the current determination (edit-in-place); default a fresh one
        // to "Under review" rather than the Undetermined baseline the picker doesn't offer.
        if (name == "materiality")
        {
            var m = _case.Materiality;
            a.MaterialityStatus = m.Status == MaterialityStatus.Undetermined ? MaterialityStatus.UnderReview : m.Status;
            a.MaterialityDecisionMaker = m.DecisionMaker;
            a.MaterialityDecidedOn = m.DecidedOnUtc?.UtcDateTime.Date;
            a.MaterialityRationale = m.Rationale;
            a.MaterialityBaseline = _case.MaterialityConcurrencyStamp(); // REL-02: optimistic-concurrency baseline
        }

        a.Transition.UseGate(name switch
        {
            "reclass" => await LoadGateAsync(CaseFlowGates.Reclassify(_case, a.NewClass)),
            "status" => await LoadGateAsync(CaseFlowGates.Phase(_case, a.NewPhase)),
            _ => null
        });
    }

    private async Task<GateEvaluation?> LoadGateAsync(StageGateTrigger? trigger)
    {
        if (trigger is not { } t) return null;
        // HR-01: closing writes the summary from the closing brief, so the summary check is met by it.
        var eval = await Cases.EvaluateGateAsync(Id, t, summaryProvided: t == StageGateTrigger.CloseCase);
        return eval.GateExists ? eval : null;
    }

    // The reclassify or phase dialog's target changed: its gate applies (RD-14: closing has a view of its own).
    private async Task TargetChanged(string which)
    {
        if (_case is null) return;
        if (which == "status" && _action.Name == "status" && _action.NewPhase == CasePhase.Closed && _case.Phase != CasePhase.Closed)
        {
            await OpenCloseOut();
            return;
        }
        _action.Transition.UseGate(await LoadGateAsync(which == "reclass"
            ? CaseFlowGates.Reclassify(_case, _action.NewClass)
            : CaseFlowGates.Phase(_case, _action.NewPhase)));
    }

    // --- RD-14: the close-out view (CaseCloseOut); its draft lives here so it survives looking elsewhere ---
    private async Task OpenCloseOut()
    {
        if (_case is null || _case.Phase == CasePhase.Closed || !_canEdit) return;
        _action.Name = null;
        _action.Error = null;
        _closeOut.Begin(WallClock.ToWall(Clock.UtcNow, TimeDisp.Zone));
        _closeOut.Transition.Gate = await LoadGateAsync(StageGateTrigger.CloseCase);   // ticks and override stay
        _closeOut.Outcomes = await Outcomes.ListActiveAsync();
        _closeOut.Prefill(_case);
        await SetTab("Closeout");
    }

    private async Task LeaveCloseOut(bool discard)
    {
        if (discard) _closeOut.Discard();
        _closeOut.Error = null;
        await SetTab(DefaultPart());
    }

    private async Task ClosedFromView(string done)
    {
        await Reload();
        Toasts.Success(done);
        await SetTab("Briefing");
    }

    private IReadOnlyDictionary<string, string> _outcomeLabels = new Dictionary<string, string>();

    private void CloseModal()
    {
        _action.Name = null;
        _action.Error = null;
    }

    // Generic confirm for destructive removes: capture a message + the action to run on confirm.
    private void AskConfirm(string message, Func<Task> onConfirm, string verb = "Remove") => _confirm = (message, verb, onConfirm);

    private void CancelConfirm() => _confirm = null;

    // FR-05: intercept in-app navigation away from this case when a composer still holds unsubmitted text,
    // and confirm before it's discarded. Same-case navigation (a tab or entity deep-link keeps the editors
    // mounted) and the security idle-lock's /session-expired landing are never blocked.
    private async Task OnBeforeInternalNav(LocationChangingContext ctx)
    {
        if (_leaveConfirmed) { _leaveConfirmed = false; return; } // already confirmed — let it through
        var target = ctx.TargetLocation;
        if (target.Contains("session-expired", StringComparison.OrdinalIgnoreCase)) return;
        if (target.Contains($"cases/{Id}", StringComparison.OrdinalIgnoreCase)) return; // same case
        if (_accessLost) return; // REL-07: the case is gone; don't block leaving after a copy-out
        if (!await AnyDraftDirtyAsync()) return;
        ctx.PreventNavigation();
        _pendingLeave = target;
        _confirmLeaveOpen = true;
        StateHasChanged();
    }

    // FR-05 / REL-07: whether any composer holds unsubmitted text (the JS editor is the source of truth).
    private async Task<bool> AnyDraftDirtyAsync()
    {
        try { return await JS.InvokeAsync<bool>("markdownEditor.anyDirty"); }
        catch { return false; } // if we can't tell, don't obstruct
    }

    private void CancelLeave()
    {
        _confirmLeaveOpen = false;
        _pendingLeave = null;
    }

    private void ConfirmLeave()
    {
        var target = _pendingLeave;
        _confirmLeaveOpen = false;
        _pendingLeave = null;
        if (target is null) return;
        _leaveConfirmed = true; // the reissued navigation passes straight through the guard
        Nav.NavigateTo(target);
    }

    // UX-01: Esc closes whichever .modal.d-block dialog is open (focus is trapped inside it, so the
    // keydown bubbles here). The JS focus-trap restores focus to the trigger on release.
    private void OnModalEscape(KeyboardEventArgs e)
    {
        if (e.Key != "Escape") return;
        if (_confirm is not null) CancelConfirm();
        else if (_confirmLeaveOpen) CancelLeave();
        else if (_previewShotId is not null) CloseShot();
        else if (_action.Name is not null) CloseModal();
    }

    // UX-01: whether any of the three trap modals is currently open (drives arm/release in OnAfterRenderAsync).
    private bool AnyTrapModalOpen => _confirm is not null || _previewShotId is not null || (_action.Name is not null && !_action.IsSheet) || _confirmLeaveOpen
        || _panelEntity is not null || _panelEvidence is not null;
    private bool _modalTrapArmed;
    private string? _revealedTab;

    private async Task RunConfirm()
    {
        var action = _confirm?.OnConfirm;
        _confirm = null;
        if (action is null) return;
        // One guard for every tab's confirm callback: a refused or stale write shows its reason instead of
        // replacing the page with the error fallback.
        try { await action(); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or ForbiddenException)
        {
            Toasts.Error(ex.Message);
        }
    }



    private async Task ActionApplied((string Done, string? CloseReason) result)
    {
        _action.Name = null;
        await Reload();
        if (result.Done.Length > 0) Toasts.Success(result.Done);
        // PROD-11: after superseding, hand straight to the close-out, closing as a duplicate with the reason as its conclusion.
        if (result.CloseReason is { } closeReason)
        {
            await AdvanceTo(CasePhase.Closed);
            if (_closeOut.Outcomes.Any(o => o.Key == IncidentManager.Application.Admin.CaseOutcomeCatalog.Duplicate))
                _closeOut.Outcome = IncidentManager.Application.Admin.CaseOutcomeCatalog.Duplicate;
            _closeOut.Conclusion = closeReason;
        }
    }

    // REL-08: access was revoked since the case loaded: close the dialog, demote the UI and explain.
    private void ActionForbidden()
    {
        _action.Name = null;
        Forbidden();
    }

    private CasePhase? NextPhase() => CaseFlow.NextPhase(_case);

    private async Task AdvanceTo(CasePhase phase)
    {
        // Every advance goes through the status dialog (FR-01 for Close's gate; INV-05 for the rest), so the
        // analyst records what was achieved and, when entering it after the fact, when it actually happened.
        await OpenModal("status");
        _action.NewPhase = phase;
        await TargetChanged("status"); // load the gate (if any) for the selected target
    }

    // HR-10: a finished Contain/Eradicate/Recover task's result becomes what was achieved; the analyst still reviews and
    // applies the change in the dialog (gate, effective time).
    private async Task AdvanceWithResult((CasePhase Phase, string Achieved, DateTimeOffset? At) offer)
    {
        await AdvanceTo(offer.Phase);
        _action.PhaseReason = offer.Achieved;
        if (offer.At is { } at) _action.Transition.When = WallClock.ToWall(at, TimeDisp.Zone);
    }



    // --- INV-15: structured handoff, prefilled from the record: the brief's situation (or the summary), what was logged
    // since the last handoff, and the open tasks. The analyst edits it before handing off.
    private void PrefillHandoff()
    {
        if (_case is null) return;
        var a = _action;
        a.HandoffTo = null;
        a.HandoffWatch = null;
        a.HandoffEmail = true;
        a.HandoffTasks = true;
        a.HandoffState = _case.Summary;   // INV-36: the summary is the brief's first part
        // INV-21: the team's work and response milestones, not the adversary's steps.
        a.HandoffDone = HandoffDraft.DoneSince(_case, new MilestoneLabels(
            c => Ui.Label(c), s => SevLabels.For(s), p => Ui.Label(p), m => Ui.Label(m)), OneLine);
        // INV-25: the same "next" list the brief and the context panel show.
        var open = CaseNext.Open(_case, Clock.UtcNow)
            .Select(t => $"- {t.Title}" + (string.IsNullOrWhiteSpace(t.Owner) ? "" : $" ({Users.DisplayFor(t.Owner)})"))
            .ToList();
        a.HandoffOpen = open.Count > 0 ? string.Join("\n", open) : null;
    }

    private string OneLine(string markdown)
    {
        var text = Md.ToPlainText(markdown).Replace('\n', ' ').Trim();
        return text.Length <= 140 ? text : text[..137] + "…";
    }


    // A stage-gate "Fix" link (from the Overview readiness card or a gate dialog): close any dialog and go to
    // what satisfies the check.
    private async Task FixGateItem(string checkKey)
    {
        _action.Name = null;
        switch (checkKey)
        {
            case GateCheckKeys.AtLeastOneEntity or GateCheckKeys.AtLeastOneMaliciousEntity or GateCheckKeys.EntitiesAssessed: await SetTab("Entities"); break;
            case GateCheckKeys.AtLeastOneEvidence: await SetTab("Evidence"); break;
            case GateCheckKeys.AtLeastOneReport: await SetTab("Report"); break;
            case GateCheckKeys.LessonsCaptured: await SetTab("Review"); break;
            case GateCheckKeys.IncidentCommanderAssigned:
                await OpenModal("assign");
                _action.AssignRole = CaseAssignmentRole.IncidentCommander;
                break;
            case GateCheckKeys.MaterialityDetermined: await OpenModal("materiality"); break;
            case GateCheckKeys.AffectedIndividualsCountSet or GateCheckKeys.MinAffectedIndividuals
                or GateCheckKeys.DataElementsSet or GateCheckKeys.AffectedStatesSet:
                // RD-11: the impact editor is in Things › Impact.
                _pendingOverviewFix = checkKey;
                await SetTab("Impact");
                break;
            default:
                // The summary and the case record's details are on the Briefing, which opens the editor.
                _pendingOverviewFix = checkKey;
                await SetTab("Briefing");
                break;
        }
    }

    // A details/impact fix raised from a gate dialog elsewhere: handed to the Briefing or Impact part once it renders.
    private string? _pendingOverviewFix;
}
