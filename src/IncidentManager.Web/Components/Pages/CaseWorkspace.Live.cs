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
/// RD-27: the workspace's live updates. A collaborator's save arrives as a change event (RD-22): the case is re-read
/// (only the parts it touched, where it can be), and what appeared flashes in that person's colour, pulses its view
/// if it's elsewhere and is named in a toast (U-30); new timeline entries get a "jump to" pill (U-32).
/// </summary>
public partial class CaseWorkspace
{
    private async Task OnCaseChangedAsync(IncidentManager.Application.Abstractions.CaseChange change)
    {
        var actorId = change.ActorId;
        await InvokeAsync(async () =>
        {
            if (_accessLost) return; // REL-07: already holding the workspace for a copy-out — don't churn it

            // RD-22: a change to the record, tasks, things, evidence, the brief or the paperwork re-reads only that part
            // of the case; anything touching the case itself (phase, rung, team, gates…) re-reads the whole case below.
            var regions = IncidentManager.Application.Cases.CaseRegionMap.Of(change);
            if (_case is not null && !regions.HasFlag(IncidentManager.Application.Cases.CaseRegions.Whole))
            {
                var known = _knownIds;
                if (await Cases.RefreshPartsAsync(_case, regions))
                {
                    if (regions.HasFlag(IncidentManager.Application.Cases.CaseRegions.Tasks))
                        _taskResults = await Cases.GetTaskResultsAsync(_case.Id);
                    _readinessEval = NextGateTrigger() is { } gt ? await LoadGateAsync(gt) : null;   // the gate reads them all
                    SeedKnownIds();
                    if (LiveRefreshFor(_activeTab, regions)) _liveRefresh++;
                    await SetTab(_activeTab);
                    FlagNewItems(known, actorId);
                    StateHasChanged();
                    return;
                }
            }

            var hadCase = _case is not null;
            var prevKnown = _knownIds; // U-30: snapshot before Reload re-seeds, so we can diff what appeared

            // REL-07: a live-collab change can be an archive/restrict that removes this case from under the
            // viewer. Peek before swapping the view: if it vanished while a composer still holds unsubmitted
            // text, don't yank the workspace out to the "not found" page (which unmounts the editors and
            // silently discards the draft — the FR-05 guard only covers navigation). Hold the workspace with
            // a banner so the viewer can copy the text out first.
            var refreshed = await Cases.GetDetailAsync(Id);
            if (refreshed is null && hadCase && await AnyDraftDirtyAsync())
            {
                _accessLost = true;
                StateHasChanged();
                return;
            }

            await ReloadWith(refreshed);
            await RefreshPermissionsAsync(); // REL-08: demote the UI if this user's access was revoked mid-session
            _liveRefresh++; // UX-13: signal extracted tabs to re-query the case (an in-progress edit in a
                            // tab component survives, since the component isn't re-created by a reload)
            await SetTab(_activeTab); // refresh the visible tab's data
            FlagNewItems(prevKnown, actorId); // U-30: flash / pulse / toast a collaborator's additions
            StateHasChanged();
        });
    }

    // RD-22: whether a part that loads its own data needs to re-query for a change to these regions. Working notes stay
    // out of the report and the lessons, so a note alone doesn't re-query those; everything else re-queries as before.
    private static bool LiveRefreshFor(string part, IncidentManager.Application.Cases.CaseRegions regions) => part switch
    {
        "Report" or "Review" => regions != IncidentManager.Application.Cases.CaseRegions.Notes,
        _ => true,
    };

    // --- U-30: live-collaboration motion --------------------------------------------------------
    // When another analyst adds something to this case, the diff of item ids (before/after reload)
    // tells us exactly what appeared. Each new item flashes in the adder's presence colour; if it
    // landed on a tab you aren't viewing, that tab pulses; and a toast names who added what. A
    // viewer's own additions don't echo, because Reload() re-seeds _knownIds before the notice lands.
    private readonly Dictionary<Guid, (int Hue, string Tab)> _flash = new(); // item id -> flash state
    private readonly Dictionary<string, int> _newOnTab = new();              // tab -> unseen new count
    private readonly HashSet<Guid> _newTimelineIds = new();                  // U-32: unseen new timeline entries
    private HashSet<Guid> _knownIds = new();
    private string? _myId;

    private string FlashClass(Guid id) => _flash.ContainsKey(id) ? "im-flash" : "";
    private string? FlashStyle(Guid id) => _flash.TryGetValue(id, out var f) ? $"--flash-hue:{f.Hue}" : null;

    private readonly record struct FeedItem(Guid Id, string Tab, string Kind);

    private IEnumerable<FeedItem> CurrentItems()
    {
        if (_case is null) yield break;
        foreach (var x in _case.TimelineEntries.Where(t => t.IsCurrent)) yield return new FeedItem(x.Id, "Timeline", "timeline entry");
        foreach (var x in _case.Entities) yield return new FeedItem(x.Id, "Entities", "entity");
        foreach (var x in _case.Evidence) yield return new FeedItem(x.Id, "Evidence", "evidence item");
        foreach (var x in _case.Notes.Where(n => n.IsCurrent)) yield return new FeedItem(x.Id, "Timeline", "note");
        foreach (var x in _case.ActionItems) yield return new FeedItem(x.Id, "Tasks", "task");
    }

    private void SeedKnownIds() => _knownIds = CurrentItems().Select(i => i.Id).ToHashSet();

    private void FlagNewItems(HashSet<Guid> prevKnown, string actorId)
    {
        if (prevKnown.Count == 0) return; // first population — nothing to diff against yet
        var added = CurrentItems().Where(i => !prevKnown.Contains(i.Id)).ToList();
        if (added.Count == 0) return; // e.g. a status change, or the viewer's own edit already absorbed

        var hue = Ui.AvatarHue(actorId);
        foreach (var it in added)
        {
            _flash[it.Id] = (hue, it.Tab);
            if (!string.Equals(it.Tab, _activeTab, StringComparison.OrdinalIgnoreCase))
                _newOnTab[it.Tab] = _newOnTab.GetValueOrDefault(it.Tab) + 1;
            if (it.Tab == "Timeline") _newTimelineIds.Add(it.Id); // U-32: feeds the "jump to new" pill
        }

        // Attribution toast — never announce your own change back to you.
        if (!string.Equals(actorId, _myId, StringComparison.OrdinalIgnoreCase))
            Toasts.Info($"{Users.DisplayFor(actorId)} {ActivityToast.Compose(added.Select(i => i.Kind))}");

        // Items already visible on the active tab have been seen — start their fade now.
        var visible = added.Where(i => string.Equals(i.Tab, _activeTab, StringComparison.OrdinalIgnoreCase))
                           .Select(i => i.Id).ToList();
        if (visible.Count > 0) _ = ClearFlashesAfter(visible);
    }

    private async Task ClearFlashesAfter(List<Guid> ids)
    {
        await Task.Delay(TimeSpan.FromSeconds(4)); // outlasts the ~3.6s flash animation, then clears the class
        await InvokeAsync(() =>
        {
            var changed = false;
            foreach (var id in ids) changed |= _flash.Remove(id);
            if (changed) StateHasChanged();
        });
    }

    // --- U-32: "jump to what just arrived" on the timeline, and a heartbeat that keeps relative
    // times ("2m ago") advancing on their own without a reload. ---
    private async Task JumpToNewTimeline()
    {
        var target = _newTimelineIds.FirstOrDefault();
        _newTimelineIds.Clear();
        if (target != Guid.Empty)
        {
            try { await JS.InvokeVoidAsync("imMotion.scrollToId", $"tl-{target}"); }
            catch { /* circuit/JS not ready — the pill still cleared */ }
        }
    }

    private System.Threading.Timer? _relativeTimeTicker;
}
