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
        if (phone && _phoneOpenedFor != Id)
        {
            _phoneOpenedFor = Id;
            if (string.IsNullOrEmpty(QTab) && QEntry is null && QNote is null && QEntity is null && QEvidence is null) _phoneTab = "Now";
        }
        return InvokeAsync(StateHasChanged);
    }

    private bool PhoneNowNext => _phone && _phoneTab is "Now" or "Next";

    private async Task PhoneGo(string tab)
    {
        if (tab is "Now" or "Next") { _phoneTab = tab; return; }
        _phoneTab = null;
        await SetView(tab);
    }

    private async Task AddTaskFromPane()
    {
        _tasksAutofocus = true;
        await SetTab("Tasks");
    }

    // The gate meter in Next opens the Briefing's readiness section, where each check has its Fix.
    private async Task ShowReadiness()
    {
        await SetTab("Briefing");
        _scrollToId = "ov-gate";
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

    private void OpenEntity(Guid id) { _panelEvidence = null; _panelEntity = id; }

    // --- RD-06: the evidence panel ---
    private Guid? _panelEvidence;

    private void OpenEvidence(Guid id) { _panelEntity = null; _panelEvidence = id; }

    private async Task CloseEvidencePanel()
    {
        _panelEvidence = null;
        try { await JS.InvokeVoidAsync("history.replaceState", null, "", Nav.GetUriWithQueryParameter("evidence", (string?)null)); }
        catch (JSException) { /* cosmetic */ }
    }

    // A citing entry opens on the timeline, flashed; the brief is in the Now pane (or on the Briefing).
    private async Task ShowCitation(Guid? entryId)
    {
        await CloseEvidencePanel();
        if (entryId is { } id) await FocusItem(("Timeline", id));
        else if (!PaneShown) await SetTab("Briefing");
    }

    private async Task CloseEntityPanel()
    {
        _panelEntity = null;
        // Drop ?entity= so a reload doesn't reopen it.
        try { await JS.InvokeVoidAsync("history.replaceState", null, "", Nav.GetUriWithQueryParameter("entity", (string?)null)); }
        catch (JSException) { /* cosmetic */ }
    }

    private async Task ShowEntityOnTimeline(Guid id)
    {
        await CloseEntityPanel();
        _timelineEntity = id;
        await SetTab("Timeline");
    }

    private async Task EntityPanelGoTo(string tab)
    {
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
    }

    // INV-33: the current brief's parts as one text, so the Evidence tab can say when the brief cites a file.
    private string? CurrentBriefText() => _case?.Briefs.FirstOrDefault(b => b.IsCurrent) is { } b
        ? string.Join('\n', b.Summary, b.WorkingAssessment, b.Known, b.OpenQuestions) : null;

    // INV-27: the timeline's changes since a given time (the brief's "N changes since").
    private async Task ShowSinceAt(DateTimeOffset since)
    {
        _timelineSince = since;
        await SetTab("Timeline");
    }

    private Guid? _watchedHeadFor;
}
