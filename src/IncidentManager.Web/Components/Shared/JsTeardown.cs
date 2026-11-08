using Microsoft.JSInterop;

namespace IncidentManager.Web.Components.Shared;

/// <summary>Telling the page's script a component has gone, where a call that can't happen isn't an error.</summary>
public static class JsTeardown
{
    /// <summary>
    /// Calls <paramref name="identifier"/> from a component's disposal, doing nothing when the tab has gone, the circuit
    /// cancelled the call while it was shutting down, nothing was rendered interactively (a prerender or a test render), or
    /// the script itself failed. A disposal that throws isn't caught by the page's error boundary: it ends the whole
    /// circuit, so a teardown that's no longer needed must never throw.
    /// </summary>
    public static async ValueTask StopAsync(this IJSRuntime js, string identifier, params object?[]? args)
    {
        try { await js.InvokeVoidAsync(identifier, args); }
        catch (JSDisconnectedException) { /* the tab has gone */ }
        catch (OperationCanceledException) { /* the circuit cancelled it on its way down */ }
        catch (InvalidOperationException) { /* not rendered interactively */ }
        catch (JSException) { /* the script failed (its element already gone): nothing left to tear down */ }
    }
}
