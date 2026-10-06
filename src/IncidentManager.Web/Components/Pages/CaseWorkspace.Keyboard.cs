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
        if (cmd == "submit")
        {
            if (!_canEdit) return;
            switch (_activeTab)
            {
                case "Timeline":
                    if (_timelineTab is not null) await _timelineTab.SubmitAsync();
                    break;
                case "Entities": if (_entitiesTab is not null) await _entitiesTab.SubmitAsync(); break;
                case "Tasks": if (_tasksTab is not null) await _tasksTab.SubmitAsync(); break;
                case "Review": if (_reviewTab is not null) await _reviewTab.SubmitAsync(); break;
                case "Briefing" or "Impact" or "Attack" or "Connections": if (_overviewTab is not null) await _overviewTab.SubmitAsync(); break;
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
