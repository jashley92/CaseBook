using IncidentManager.Application.Preferences;
using Microsoft.JSInterop;

namespace IncidentManager.Web.Services;

/// <summary>RD-24: hands a user's keymap to the browser's dispatcher (wwwroot/js/keymap.js).</summary>
public static class KeymapClient
{
    public static object Config(KeymapSettings s) => new
    {
        singleOff = s.SingleKeysOff,
        bindings = Keymap.Actions.SelectMany(a => s.KeysFor(a)
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(k => new { keys = k, scope = a.Scope == KeyScope.Case ? "case" : "any", command = a.Command }))
            .ToList(),
    };

    public static async Task ApplyAsync(IJSRuntime js, KeymapSettings s)
    {
        try { await js.InvokeVoidAsync("imKeymap.configure", Config(s)); }
        catch (JSException) { /* the dispatcher isn't loaded; keys just don't work */ }
        catch (JSDisconnectedException) { }
        catch (InvalidOperationException) { /* prerendering */ }
    }
}
