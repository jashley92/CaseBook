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
/// RD-27: the case's keyboard shortcuts (U-14, RD-24's keymap): views by digit, log, task, note, and save.
/// </summary>
public partial class CaseWorkspace
{
    /// <summary>U-14: a case-local keyboard shortcut fired by the keymap dispatcher (RD-24, keymap.js).</summary>
    [JSInvokable]
    public async Task OnCaseHotkey(string cmd)
    {
        if (_case is null || string.IsNullOrEmpty(cmd)) return;

        // Ctrl/Cmd+Enter — submit the composer active on the current tab. Each add/save method guards its
        // required fields, so a submit with nothing to post is a harmless no-op.
        if (cmd is "submit" or "submit:action" or "submit:dialog")
        {
            // BUG-328: what's open on top takes it. The action dialog or sheet applies when the keys were pressed in it
            // (its own guard and disabled state hold, BUG-14); a sheet isn't modal, so pressed outside it they submit the
            // tab's composer as usual. A confirm, the leave guard, the screenshot or a side panel ignores it, as does any
            // other dialog it came from, such as the timeline's correction dialog. BUG-370: keymap.js says which:
            // "submit:action" only from inside the action dialog or sheet, "submit:dialog" from any other dialog or panel
            // (so a sheet open behind the entity panel isn't applied), and nothing from regions with their own keys.
            if (_confirm is not null || _confirmLeaveOpen || _previewShotId is not null || cmd == "submit:dialog") return;
            if (_action.Name is not null && (cmd == "submit:action" || !_action.IsSheet))
            {
                if (_actionForm is not null) await _actionForm.SubmitAsync();
                return;
            }
            if (cmd == "submit:action" || _panelEntity is not null || _panelEvidence is not null) return;
            if (!_canEdit) return;
            // BUG-425: the phone's Now/Next view replaces the tab, and a tab that threw shows the error fallback. Either way
            // the @ref still points at the tab removed (Disposed), so there's no composer on the page to submit. Forms
            // with their own submit (.im-own-keys) never get here: keymap.js leaves Ctrl/Cmd+Enter to them.
            if (PhoneNowNext) return;
            switch (_activeTab)
            {
                case "Timeline": if (_timelineTab is { Disposed: false } tl) await tl.SubmitAsync(); break;
                case "Entities": if (_entitiesTab is { Disposed: false } en) await en.SubmitAsync(); break;
                case "Tasks": if (_tasksTab is { Disposed: false } ta) await ta.SubmitAsync(); break;
                case "Review": if (_reviewTab is { Disposed: false } rv) await rv.SubmitAsync(); break;
                case "Briefing" or "Impact" or "Attack" or "Connections":
                    if (_overviewTab is { Disposed: false } ov) await ov.SubmitAsync();
                    break;
            }
            return;
        }

        // RD-11: digits pick the views in order.
        if (cmd.StartsWith("tab:", StringComparison.Ordinal)
            && int.TryParse(cmd.AsSpan(4), out var digit) && (digit == 0 ? 10 : digit) is var n
            && n >= 1 && n <= CaseViews.All.Length)
        {
            await SetView(CaseViews.All[n - 1].View);
            StateHasChanged();
            return;
        }

        if (cmd == "note" && _canEdit)
        {
            // RD-08: 'n' opens the composer in Working note mode on the Timeline's notes lens.
            _timelineAutofocus = true;
            await SetTab("Notes");
            StateHasChanged();
        }

        // INV-14: capture from any tab — 'l' logs an investigation entry on the timeline, 't' adds a task.
        if (cmd == "log" && _canEdit)
        {
            _timelineAutofocus = true;
            await SetTab("Timeline");
            StateHasChanged();
        }
        if (cmd == "task" && _canEdit)
        {
            _tasksAutofocus = true;
            await SetTab("Tasks");
            StateHasChanged();
        }
    }
}
