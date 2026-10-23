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
/// RD-27: what sits beside or over the case's views: the Now/Next pane (RD-04) and its acts, the phone layout (RD-25),
/// the entity and evidence panels (INV-11, RD-06), and "since you last viewed" (INV-04).
/// </summary>
public partial class CaseWorkspace
{
    // --- INV-12 / RD-04: the Now/Next pane beside the tabs (wide screens) ---
    private bool _railOpen = true;
    // Whether the viewport is wide enough for the pane (reported by imMedia; assumed until it says otherwise).
    private bool _wide = true;
    // RD-12: the Briefing has the brief and its own obligations, governance and team, so the pane steps aside there.
    private bool PaneShown => _railOpen && _wide && _activeTab is not ("Briefing" or "Closeout");
    private CaseNowNext? _nowNext;

    /// <summary>RD-04: imMedia reports whether the pane fits (min-width 1200px).</summary>
    [JSInvokable]
    public Task OnMediaChanged(bool wide)
    {
        if (_wide == wide) return Task.CompletedTask;
        _wide = wide;
        return InvokeAsync(StateHasChanged);
    }

    // --- RD-25: phone layout. A case opens on Now; Now · Record · Next · Things are tabs along the bottom (with More for
    // Tasks, Briefing and Paper). Acts that need room (phase changes, gates, closing, reports) say they're done at a desk.
    private bool _phone;
    private string? _phoneTab;          // "Now" or "Next" while one of those is showing; null = the active view
    private Guid _phoneOpenedFor;

    [JSInvokable]
    public Task OnPhoneChanged(bool phone)
    {
        if (_phone == phone) return Task.CompletedTask;
        _phone = phone;
        if (phone && _phoneOpenedFor != Id) OpenOnPhone();
        return InvokeAsync(StateHasChanged);
    }

    // RD-25: a case opens on Now on a phone, unless a link points somewhere in it. BUG-491: also on a move to another case
    // within the workspace, so the last case's Now/Next or view isn't kept over the new one, nor over its link's target.
    private void OpenOnPhone()
    {
        _phoneOpenedFor = Id;
        _phoneTab = HasDeepLink ? null : "Now";
    }

    private bool HasDeepLink => !string.IsNullOrEmpty(QPart) || QEntry is not null || QNote is not null || QEntity is not null || QEvidence is not null;

    private bool PhoneNowNext => _phone && _phoneTab is "Now" or "Next";

    // BUG-578: the phone's Now/Next replaces the tab body, and a view replaces Now/Next: either asks before hiding text.
    private async Task PhoneGo(string tab)
    {
        if (tab is "Now" or "Next")
        {
            if (await HoldForUnsavedAsync($"show {tab}", "Discard & switch", () => PhoneGo(tab), LostBy(_activeTab, tab))) return;
            _phoneTab = tab;
            return;
        }
        var part = PartOfView(tab);
        if (await HoldForUnsavedAsync(SwitchDoing(part), "Discard & switch", () => PhoneGo(tab), LostBy(part, null))) return;
        _phoneTab = null;
        await ShowTab(part);
    }

    // The phone's Now/Next sends the viewer elsewhere (a tab, a task): it goes away first, once any text in it is let go.
    private async Task LeavePhonePane(Func<Task> then)
    {
        if (await HoldForUnsavedAsync("leave Now and next", "Discard & continue", () => LeavePhonePane(then), _paneRegion)) return;
        _phoneTab = null;
        await then();
    }

    // RD-04: hiding the pane unmounts it.
    private async Task ToggleRail()
    {
        if (_railOpen && PaneShown && await HoldForUnsavedAsync("hide Now and next", "Discard & hide", ToggleRail, _paneRegion)) return;
        _railOpen = !_railOpen;
    }

    private async Task AddTaskFromPane()
    {
        _tasksAutofocus = true;
        await SetTab("Tasks");
        if (!Showing("Tasks")) _tasksAutofocus = false;   // BUG-719: held for unsaved text
    }

    // CAP-11: the playbook notice's "Add them…" opens the Tasks tab's apply card on that playbook (nothing is added until
    // it's applied there). Pending until the Tasks tab takes it; going to any other tab lets it go (ShowTab).
    private async Task OfferPlaybook(Guid templateId)
    {
        _offerTemplate = templateId;
        if (PhoneNowNext) await LeavePhonePane(() => SetTab("Tasks"));
        else await SetTab("Tasks");
        if (!Showing("Tasks") && _offerTemplate == templateId) _offerTemplate = null;   // BUG-719: held for unsaved text
    }

    // The gate meter in Next opens the Briefing's readiness section, where each check has its Fix.
    private async Task ShowReadiness()
    {
        await SetTab("Briefing");
        if (Showing("Briefing")) _scrollToId = "ov-gate";   // BUG-719: not when the switch was held
    }

    // INV-29: the team lives in the context panel, so removing someone is confirmed from there. S-08: on a
    // restricted case, say that removal takes their access away unless their role is cleared.
    private void UnassignFromPanel(CaseAssignment a)
    {
        if (_case is null) return;
        var name = Users.DisplayFor(a.UserId);
        var prompt = _case.IsRestricted
            ? $"Remove {name} from this case? It's restricted, so they lose access to it unless their role is cleared for restricted cases."
            : $"Remove {name} from this case?";
        AskConfirm(prompt, async () =>
        {
            await Cases.UnassignAsync(_case.Id, a.UserId);
            await Reload();
            Toasts.Success("Assignment removed");
        });
    }

    // --- INV-11: the entity panel ---
    private Guid? _panelEntity;
    private Guid? _timelineEntity;

    // BUG-578 (C7-9): a panel moved to another item, or closed, unmounts its forms; with text in them that waits for a yes.
    private Task<bool> HoldPanelAsync(Guid? nextEntity, Guid? nextEvidence, Func<Task> again) =>
        (_panelEntity is not null && _panelEntity != nextEntity) || (_panelEvidence is not null && _panelEvidence != nextEvidence)
            ? HoldForUnsavedAsync("leave this panel", "Discard & continue", again, _panelRegion)
            : Task.FromResult(false);

    private async Task OpenEntity(Guid id)
    {
        if (await HoldPanelAsync(id, null, () => OpenEntity(id))) return;
        var hadEvidence = _panelEvidence is not null;
        _panelEvidence = null;
        _panelEntity = id;
        if (hadEvidence) await SyncTabUrl();   // BUG-489: the evidence panel it replaces leaves the address
    }

    // --- RD-06: the evidence panel ---
    private Guid? _panelEvidence;

    private async Task OpenEvidence(Guid id)
    {
        if (await HoldPanelAsync(null, id, () => OpenEvidence(id))) return;
        _panelEntity = null;
        _panelEvidence = id;
        await SyncTabUrl();   // BUG-489: the address carries the open panel as a cited-file link's does
    }

    // BUG-489: the address bar and the tab strip's return both drop the closed panel.
    private async Task CloseEvidencePanel()
    {
        if (await HoldPanelAsync(null, null, CloseEvidencePanel)) return;
        _panelEvidence = null;
        await SyncTabUrl();
    }

    // A citing entry opens on the timeline, flashed; the brief is in the Now pane (or on the Briefing).
    private async Task ShowCitation(Guid? entryId)
    {
        if (await HoldPanelAsync(null, null, () => ShowCitation(entryId))) return;
        await CloseEvidencePanel();
        if (entryId is { } id) await FocusItem(("Timeline", id));
        else if (!PaneShown) await SetTab("Briefing");
    }

    private async Task CloseEntityPanel()
    {
        if (await HoldPanelAsync(null, null, CloseEntityPanel)) return;
        _panelEntity = null;
        // Drop ?entity= so a reload doesn't reopen it (BUG-489: from the current part, and the tab strip's return too).
        await SyncTabUrl();
    }

    private async Task ShowEntityOnTimeline(Guid id)
    {
        if (await HoldPanelAsync(null, null, () => ShowEntityOnTimeline(id))) return;
        await CloseEntityPanel();
        _timelineEntity = id;
        await SetTab("Timeline");
        if (!Showing("Timeline") && _timelineEntity == id) _timelineEntity = null;   // BUG-719: held for unsaved text
    }

    private async Task EntityPanelGoTo(string tab)
    {
        if (await HoldPanelAsync(null, null, () => EntityPanelGoTo(tab))) return;
        await CloseEntityPanel();
        await SetTab(tab);
    }

    // --- INV-04: since you last viewed ---
    private Guid? _sinceCheckedFor;
    private DateTimeOffset? _lastViewed;
    private int _sinceCount;
    private (IncidentManager.Application.Cases.AfterClosureChanges Changes, IReadOnlyList<string> People)? _afterClosure;   // HR-15
    private IReadOnlyList<string> _sincePeople = [];
    private bool _sinceDismissed;
    private DateTimeOffset? _timelineSince;

    private async Task ShowSinceOnTimeline()
    {
        _timelineSince = _lastViewed;
        await SetTab("Timeline");
        if (!Showing("Timeline")) _timelineSince = null;   // BUG-719
    }

    // INV-33: the current brief's parts as one text, so the Evidence tab can say when the brief cites a file.
    private string? CurrentBriefText() => _case?.Briefs.FirstOrDefault(b => b.IsCurrent) is { } b
        ? string.Join('\n', b.Summary, b.WorkingAssessment, b.Known, b.OpenQuestions) : null;

    // INV-27: the timeline's changes since a given time (the brief's "N changes since").
    private async Task ShowSinceAt(DateTimeOffset since)
    {
        _timelineSince = since;
        await SetTab("Timeline");
        if (!Showing("Timeline")) _timelineSince = null;   // BUG-719
    }

    private Guid? _watchedHeadFor;
}
