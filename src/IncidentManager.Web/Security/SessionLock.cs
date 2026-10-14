using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace IncidentManager.Web.Security;

/// <summary>
/// The one way a circuit locks itself (F-15 idle lock, S-24 "Lock now"). A full-page load to the lock page
/// tears the circuit down. BUG-327: both callers go through here so neither can forget to suppress the
/// composer's unsaved-changes <c>beforeunload</c> prompt first (FR-05), which would otherwise hold the
/// navigation at the browser's "Leave site?" dialog and leave the session open.
/// </summary>
public static class SessionLock
{
    public static async Task LockAsync(IJSRuntime js, NavigationManager nav, string target)
    {
        try { await js.InvokeVoidAsync("markdownEditor.suppressUnloadGuard"); }
        catch (JSDisconnectedException) { /* circuit already gone */ }
        catch (JSException) { /* best effort: never let the guard block the lock */ }
        nav.NavigateTo(target, forceLoad: true);
    }
}
