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
    private Task OpenModal(string name) => TryOpenModal(name, () => OpenModal(name));

    // BUG-578 (C7-10): what the open dialog's input is called in the Stay / Discard prompt.
    private const string ActionWhat = "the change you're making";

    // BUG-578: opening a dialog starts its fields, and the transition's time, ticks and override, over. Over an open dialog
    // (a sheet isn't modal, and the palette works over a modal) with input in it, that waits for Stay / Discard; Discard
    // runs `again`, the whole act that opened it. False when it didn't open.
    private bool HoldOpenAction(string doing, Func<Task> again)
    {
        if (_letGo.Contains(_actionRegion) || !ActionDirty()) return false;
        _discard ??= new(ActionWhat, doing, "Discard & continue", again, [_actionRegion]);
        return true;
    }

    private async Task<bool> TryOpenModal(string name, Func<Task> again)
    {
        if (_case is null || HoldOpenAction("start another action", again)) return false;
        var seq = ++_gateSeq;
        var a = _action;
        a.Open(name);
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
        // FR-51: moving on from Containment before it was marked contained asks when it was; that starts at now.
        if (name == "status" && _case.Phase == CasePhase.Containment && _case.ContainedAtUtc is null)
            a.ContainedAt = WallClock.ToMinute(WallClock.ToWall(Clock.UtcNow, TimeDisp.Zone));

        if (name == "holdrelease") a.HoldReleaseReason = null;   // don't carry a cancelled attempt's text over
        if (name == "handoff")
        {
            var people = await Cases.MentionableAsync(Id);
            // BUG-601: PrefillHandoff reads the case and dialog open now, which a case switch or another dialog replaced.
            if (seq != _gateSeq || a != _action || _case is null) return false;
            a.HandoffPeople = people;
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
            // BUG-07: a date and time in the viewer's zone; a new determination defaults to now. BUG-227: so does one
            // still under review, whose call hasn't been made yet: an older time kept from then would date the decision
            // (and start the notification clock) from when the review began.
            var decided = m.Status is MaterialityStatus.Material or MaterialityStatus.NotMaterial
                ? m.DecidedOnUtc ?? Clock.UtcNow
                : Clock.UtcNow;
            var wall = WallClock.ToWall(decided, TimeDisp.Zone);
            a.MaterialityDecidedOn = wall.AddSeconds(-wall.Second).AddMilliseconds(-wall.Millisecond);
            a.MaterialityDecidedOnRecorded = m.Status is MaterialityStatus.Material or MaterialityStatus.NotMaterial ? m.DecidedOnUtc : null;
            a.MaterialityRationale = m.Rationale;
            a.MaterialityBaseline = _case.MaterialityConcurrencyStamp(); // REL-02: optimistic-concurrency baseline
        }

        if (seq != _gateSeq || a != _action) return false;   // BUG-488: another dialog or case took over while this loaded
        SeedAction();   // BUG-578: what it opened with is not "typed"
        var gate = name switch
        {
            "reclass" => await LoadClimbGatesAsync(a.NewClass),
            "status" => await LoadGateAsync(CaseFlowGates.Phase(_case, a.NewPhase)),
            _ => null
        };
        if (seq != _gateSeq) return false;   // BUG-488: another dialog, target or case took over while this loaded
        a.Transition.UseGate(gate);
        return true;
    }

    // BUG-488: a dialog's opening, a change of its target, the close-out and a case switch each load a gate, and a
    // slower load overtaken by a later one would show the wrong rung's checklist and clear the ticks; only the newest
    // is kept (as CreateCase, BUG-447).
    private int _gateSeq;

    // BUG-60: a reclassification passes the gate of every rung it climbs, shown as one checklist.
    private async Task<GateEvaluation?> LoadClimbGatesAsync(Classification to)
    {
        var eval = await Cases.EvaluateClimbAsync(Id, to);
        return eval.GateExists ? eval : null;
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
        var seq = ++_gateSeq;
        var gate = which == "reclass"
            ? await LoadClimbGatesAsync(_action.NewClass)
            : await LoadGateAsync(CaseFlowGates.Phase(_case, _action.NewPhase));
        if (seq != _gateSeq) return;   // BUG-488
        _action.Transition.UseGate(gate);
    }

    // --- RD-14: the close-out view (CaseCloseOut); its draft lives here so it survives looking elsewhere ---
    private async Task OpenCloseOut()
    {
        if (_case is null || _case.Phase == CasePhase.Closed || !_canEdit) return;
        _action.Name = null;
        _action.Error = null;
        // BUG-488: loaded first, so a close-out overtaken by a dialog or a case switch while it loaded changes nothing.
        var seq = ++_gateSeq;
        var gate = await LoadGateAsync(StageGateTrigger.CloseCase);
        var outcomes = await Outcomes.ListActiveAsync();
        if (seq != _gateSeq || _case is null) return;
        _closeOut.Begin(WallClock.ToWall(Clock.UtcNow, TimeDisp.Zone));
        _closeOut.Transition.Gate = gate;   // ticks and override stay
        _closeOut.Outcomes = outcomes;
        _closeOut.Prefill(_case);
        await SetTab("Closeout");
    }

    // BUG-578: the view bar's Close-out closes an open dialog (its ticks, time and override start over next time).
    private Task OpenCloseOutFromBar() =>
        HoldOpenAction("open the close-out", OpenCloseOutFromBar) ? Task.CompletedTask : OpenCloseOut();

    private async Task LeaveCloseOut(bool discard)
    {
        if (discard) _closeOut.Discard();
        _closeOut.Error = null;
        await SetTab(DefaultPart());
    }

    private async Task ClosedFromView(CaseActionApplied result)
    {
        // BUG-337: closed after a switch to another case: say so, and leave this case (and its close-out draft) alone.
        if (!result.IsFor(Id)) { Toasts.Success(result.ElsewhereMessage); return; }
        _closeOut.Discard();
        await Reload();
        Toasts.Success(result.Done);
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
    // mounted) and the security idle-lock's /session-expired landing are never blocked. BUG-578: "unsubmitted text" is
    // everything UnsavedEdits knows of (plain fields, an open dialog, the timeline's stashed draft), not only the
    // markdown editors.
    private async Task OnBeforeInternalNav(LocationChangingContext ctx)
    {
        if (_leaveConfirmed) { _leaveConfirmed = false; return; } // already confirmed — let it through
        var target = ctx.TargetLocation;
        if (target.Contains("session-expired", StringComparison.OrdinalIgnoreCase)) return;
        if (target.Contains($"cases/{Id}", StringComparison.OrdinalIgnoreCase)) return; // same case
        if (_accessLost) return; // REL-07: the case is gone; don't block leaving after a copy-out
        var pending = await Edits.PendingAsync();
        if (pending.Count == 0) return;
        ctx.PreventNavigation();
        _discard = new(UnsavedEdits.Describe(pending), "leave now", "Leave & discard", () =>
        {
            _leaveConfirmed = true; // the reissued navigation passes straight through the guard
            Nav.NavigateTo(target);
            return Task.CompletedTask;
        }, []);
        StateHasChanged();
    }

    // FR-05 / REL-07: whether anything on the page holds unsaved input (BUG-578: UnsavedEdits, markdown included).
    private async Task<bool> AnyDraftDirtyAsync() => (await Edits.PendingAsync()).Count > 0;

    // --- BUG-578 (C7): the Stay / Discard prompt, for leaving the case and for whatever hides an editor ---------------
    // What it says is unsaved, what would lose it, its discard button, the regions it asked about, and what Discard does:
    // the act that was held runs again with those regions let go (_letGo), so it does exactly what it would have done. A
    // part of that act that would hide text somewhere else still asks about that.
    private sealed record DiscardPrompt(string What, string Doing, string Verb, Func<Task> Proceed, EditRegion[] Regions);
    private DiscardPrompt? _discard;
    private EditRegion[] _letGo = [];
    private bool DiscardOpen => _discard is not null;

    // The open action dialog, as a region of its own for _letGo (it has no element: ActionDirty is the workspace's).
    private readonly EditRegion _actionRegion = new("action", "#ws-sheet, .im-action-host");

    private async Task CancelLeave()
    {
        _discard = null;
        await SyncTabUrl();   // a ?tab= link that was held leaves the address on the part still open
    }

    private async Task ConfirmLeave()
    {
        var prompt = _discard;
        _discard = null;
        if (prompt is null) return;
        var before = _letGo;
        _letGo = [.. before, .. prompt.Regions];
        try { await prompt.Proceed(); }
        finally { _letGo = before; }
    }

    /// <summary>BUG-578: whether <paramref name="again"/> waits for a Stay / Discard answer, because what's about to
    /// happen unmounts <paramref name="lost"/> with unsaved input in it. True: the prompt is up and the caller stops;
    /// Discard runs <paramref name="again"/> with those regions let go.</summary>
    private async Task<bool> HoldForUnsavedAsync(string doing, string verb, Func<Task> again, params EditRegion[] lost)
    {
        lost = lost.Except(_letGo).ToArray();
        if (lost.Length == 0 || _case is null) return false;
        if (_discard is not null) return true;   // already asking
        // FR-02: the timeline's add composer is stashed on a tab switch and comes back, so its text isn't lost by one.
        var pending = await Edits.PendingAsync([StashedComposerId], lost);
        if (_discard is not null) return true;
        if (pending.Count == 0) return false;
        _discard = new(UnsavedEdits.Describe(pending), doing, verb, again, lost);
        StateHasChanged();
        return true;
    }

    // CaseTimelineTab's InvEditorId: the one editor whose text the workspace keeps across a tab switch (FR-02).
    private string StashedComposerId => $"inv-md-{_case?.Id}";

    // BUG-578: where the workspace's editors live (cascaded to its parts; see UnsavedEdits and EditRegion).
    private readonly EditRegion _tabRegion = new("tab", ".ws-body .tabbody");
    private readonly EditRegion _paneRegion = new("pane", ".ws-body .im-nownext");
    private readonly EditRegion _panelRegion = new("panel", ".im-entity-panel");

    // The regions a move to (part, phone view) would unmount: the tab body when another part (or the phone's Now/Next)
    // replaces it, and the Now/Next pane when it steps aside (RD-12) or the phone leaves it.
    private EditRegion[] LostBy(string tab, string? phoneTab)
    {
        if (string.Equals(tab, "Notes", StringComparison.OrdinalIgnoreCase)) tab = "Timeline";   // RD-08
        var lost = new List<EditRegion>(2);
        var phonePaneThen = _phone && phoneTab is "Now" or "Next";
        if (!PhoneNowNext && (phonePaneThen || !string.Equals(tab, _activeTab, StringComparison.Ordinal))) lost.Add(_tabRegion);
        var paneThen = phonePaneThen || (_railOpen && _wide && tab is not ("Briefing" or "Closeout"));
        if ((PaneShown || PhoneNowNext) && !paneThen) lost.Add(_paneRegion);
        return lost.ToArray();
    }

    private static string SwitchDoing(string tab) => $"switch to {CaseViews.Label(tab is "Notes" ? "Timeline" : tab)}";

    // BUG-578: the open action dialog's input, compared with what it opened with (its prefill), so an untouched dialog
    // never holds anything up. Text typed into a cancelled dialog stays in _action for the page's life, as before.
    private string? _actionSeed;
    private void SeedAction() => _actionSeed = _action.Name is null ? null : _action.InputSnapshot();
    private bool ActionDirty() => _action.Name is not null && _actionSeed is not null && _action.InputSnapshot() != _actionSeed;

    // RD-14: a close-out with a conclusion, a reply pasted in or a time or justification set.
    private bool CloseOutDirty() => _closeOut.Open
        && (!string.IsNullOrWhiteSpace(_closeOut.Conclusion) || !string.IsNullOrWhiteSpace(_closeOut.AiReply)
            || _closeOut.Transition.Edited || !string.IsNullOrWhiteSpace(_closeOut.Transition.Override));

    // UX-01: Esc closes whichever .modal.d-block dialog is open (focus is trapped inside it, so the
    // keydown bubbles here). The JS focus-trap restores focus to the trigger on release.
    private async Task OnModalEscape(KeyboardEventArgs e)
    {
        if (e.Key != "Escape") return;
        if (_confirm is not null) CancelConfirm();
        else if (DiscardOpen) await CancelLeave();
        else if (_previewShotId is not null) CloseShot();
        else if (_action.Name is not null) CloseModal();
    }

    // UX-01: which trap is on top, if any (drives arm/release in OnAfterRenderAsync). BUG-88: a dialog opened over a side
    // panel takes focus, and closing it hands focus back to the panel rather than to the page behind both.
    private string? TopTrap =>
        _confirm is not null || _previewShotId is not null || (_action.Name is not null && !_action.IsSheet) || DiscardOpen ? "dialog"
        : _panelEntity is not null || _panelEvidence is not null ? "panel"
        : null;
    private string? _armedTrap;
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



    private async Task ActionApplied(CaseActionApplied result)
    {
        // BUG-179/BUG-337: the follow-up (a reload, the close-out a supersede opens, "Duplicate of ...") belongs to the
        // case the action was for. A case switch removes the form while it saves, so the check is made here.
        if (!result.IsFor(Id)) { Toasts.Success(result.ElsewhereMessage); return; }
        // BUG-448: it may have finished after its dialog was closed, and another (or the same one, reopened) opened since;
        // that one stays open with what has been typed in it.
        var stillOpen = result.Opening == _action.Opening;
        if (stillOpen) _action.Name = null;
        await Reload();
        // BUG-601: and again after every wait, since the view can move to another case while the case reloads or the
        // close-out loads: that case's close-out mustn't be opened, or filled in as a duplicate.
        if (!result.IsFor(Id)) { Toasts.Success(result.ElsewhereMessage); return; }
        if (result.Done.Length > 0) Toasts.Success(result.Done);
        // PROD-11: after superseding, hand straight to the close-out, closing as a duplicate with the reason as its conclusion.
        if (result.CloseReason is { } closeReason && (stillOpen || _action.Name is null))
        {
            await AdvanceTo(CasePhase.Closed);
            if (!result.IsFor(Id) || !_closeOut.Open || !_closeOut.IsFor(result.CaseId)) return;
            if (_closeOut.Outcomes.Any(o => o.Key == IncidentManager.Application.Admin.CaseOutcomeCatalog.Duplicate))
                _closeOut.Outcome = IncidentManager.Application.Admin.CaseOutcomeCatalog.Duplicate;
            _closeOut.Conclusion = closeReason;
        }
    }

    // REL-08: access was revoked since the case loaded: close the dialog, demote the UI and explain.
    private void ActionForbidden(CaseActionFor action)
    {
        if (ForbiddenElsewhere(action)) return;
        _action.Name = null;
        Forbidden();
    }

    // The close-out view was refused (REL-08).
    private void CloseOutForbidden(CaseActionFor action)
    {
        if (ForbiddenElsewhere(action)) return;
        Forbidden();
    }

    // BUG-337: a refusal for the case left behind doesn't demote the one now open; it only says what happened.
    private bool ForbiddenElsewhere(CaseActionFor action)
    {
        if (action.IsFor(Id)) return false;
        Toasts.Error($"{action.Number}: {PermissionLostMessage}");
        return true;
    }

    private CasePhase? NextPhase() => CaseFlow.NextPhase(_case);

    private Task AdvanceTo(CasePhase phase) => AdvanceToCore(phase, () => AdvanceTo(phase));

    // Every advance goes through the status dialog (FR-01 for Close's gate; INV-05 for the rest), so the analyst records
    // what was achieved and, when entering it after the fact, when it actually happened. BUG-578: false when it waits
    // for Stay / Discard over another dialog's input (then `again` runs on Discard).
    private async Task<bool> AdvanceToCore(CasePhase phase, Func<Task> again)
    {
        if (!await TryOpenModal("status", again)) return false;
        _action.NewPhase = phase;
        await TargetChanged("status"); // load the gate (if any) for the selected target
        return true;
    }

    // HR-10: a finished Contain/Eradicate/Recover task's result becomes what was achieved; the analyst still reviews and
    // applies the change in the dialog (gate, effective time).
    private async Task AdvanceWithResult((CasePhase Phase, string Achieved, DateTimeOffset? At) offer)
    {
        if (!await AdvanceToCore(offer.Phase, () => AdvanceWithResult(offer)) || _action.Name != "status") return;
        _action.PhaseReason = offer.Achieved;
        // BUG-582: the offered instant is kept while its minute is left as shown (WallClock.Kept), not re-read from the wall.
        if (offer.At is { } at) _action.Transition.KeptAt(at, TimeDisp.Zone);
        SeedAction();   // BUG-578: the offer is what it opened with
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
            c => Ui.Label(c), s => SevLabels.For(s), p => Ui.Label(p), m => Ui.Label(m), Day: t => TimeDisp.DateOnly(t),
            Standing: _notifyDeadlines?.Standing), OneLine);   // CAP-38 review: reported by the standing
        // INV-25: the same "next" list the brief and the context panel show.
        var open = CaseNext.Open(_case, Clock.UtcNow)
            .Select(t => $"- {t.Title}" + (string.IsNullOrWhiteSpace(t.Owner) ? "" : $" ({Users.DisplayFor(t.Owner)})"))
            .ToList();
        a.HandoffOpen = open.Count > 0 ? string.Join("\n", open) : null;
    }

    private string OneLine(string markdown)
    {
        var text = Md.ToPlainText(markdown).Replace('\n', ' ').Trim();
        return IncidentManager.Application.Common.TextFit.Cap(text, 140);   // C12: never longer than the line, nor half an emoji
    }


    // A stage-gate "Fix" link (from the Overview readiness card or a gate dialog): close any dialog and go to
    // what satisfies the check.
    private async Task FixGateItem(string checkKey)
    {
        // BUG-578: going to the fix closes the dialog, whose ticks, time and override then start over.
        if (HoldOpenAction("go to what fixes it", () => FixGateItem(checkKey))) return;
        _action.Name = null;
        switch (checkKey)
        {
            case GateCheckKeys.AtLeastOneEntity or GateCheckKeys.AtLeastOneMaliciousEntity: await SetTab("Entities"); break;
            case GateCheckKeys.EntitiesAssessed:
                // CAP-02: "Assess" opens the tab with the Unknown ones selected, ready for one verdict.
                _entitiesPickUnknown = true;
                await SetTab("Entities");
                if (_activeTab != "Entities") _entitiesPickUnknown = false;   // the switch was held for unsaved text
                break;
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
                // BUG-703: held for unsaved text, the Briefing still showing would be handed the fix, pass it back here
                // and raise the prompt again, for good (Stay could never dismiss it).
                if (_activeTab != "Impact") _pendingOverviewFix = null;
                break;
            default:
                // The summary and the case record's details are on the Briefing, which opens the editor.
                _pendingOverviewFix = checkKey;
                await SetTab("Briefing");
                if (_activeTab != "Briefing") _pendingOverviewFix = null;   // BUG-703: as above
                break;
        }
    }

    // A details/impact fix raised from a gate dialog elsewhere: handed to the Briefing or Impact part once it renders.
    private string? _pendingOverviewFix;
    // CAP-02: the Closure gate's "Assess": the Entities tab selects the Unknown ones when it next renders.
    private bool _entitiesPickUnknown;
}
