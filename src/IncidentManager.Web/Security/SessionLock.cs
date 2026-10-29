using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace IncidentManager.Web.Security;

/// <summary>
/// The one way a circuit locks itself (F-15 idle lock, S-24 "Lock now"). A full-page load to the lock page
/// tears the circuit down. BUG-327: both callers go through here so neither can forget to suppress the
/// composer's unsaved-changes <c>beforeunload</c> prompt first (FR-05), which would otherwise hold the
/// navigation at the browser's "Leave site?" dialog and leave the session open. BUG-369: the suppression also stops
/// every other page's <c>beforeunload</c>, including Blazor's own from <c>NavigationLock ConfirmExternalNavigation</c>.
/// The tab also keeps the page it's on, so Resume returns to it (<see cref="IncidentManager.Application.Security.LockReturnPage"/>).
/// </summary>
public static class SessionLock
{
    public static async Task LockAsync(IJSRuntime js, NavigationManager nav, string target)
    {
        await BestEffortAsync(js, "imIdle.rememberPage");
        await BestEffortAsync(js, "markdownEditor.suppressUnloadGuard");
        nav.NavigateTo(target, forceLoad: true);
    }

    private static async Task BestEffortAsync(IJSRuntime js, string identifier)
    {
        try { await js.InvokeVoidAsync(identifier); }
        catch (JSDisconnectedException) { /* circuit already gone */ }
        catch (JSException) { /* best effort: never let either step block the lock */ }
    }
}
