using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;

namespace IncidentManager.Web.Security;

/// <summary>
/// S-10: the circuit's auth-state provider, re-checking the signed-in user's roles and permissions every
/// <see cref="Interval"/> against the current role directory (<see cref="SessionPermissionRefresher"/>). When they've
/// changed it publishes the updated principal, so page authorization, AuthorizeViews and service-level checks all
/// follow — someone whose access is removed loses it within minutes instead of whenever they next reconnect, and
/// someone granted access gets it without reloading.
/// </summary>
public sealed class PermissionRevalidatingAuthStateProvider : ServerAuthenticationStateProvider, IDisposable
{
    /// <summary>How often an open session's access is re-derived. In-memory lookups only, so cheap.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromMinutes(2);

    private readonly SessionPermissionRefresher _refresher;
    private readonly ILogger<PermissionRevalidatingAuthStateProvider> _log;
    private readonly CancellationTokenSource _stop = new();
    private bool _looping;
    private bool _publishing;

    public PermissionRevalidatingAuthStateProvider(SessionPermissionRefresher refresher,
        ILogger<PermissionRevalidatingAuthStateProvider> log)
    {
        _refresher = refresher;
        _log = log;
        AuthenticationStateChanged += OnChanged;
    }

    // The host sets the circuit's initial state once; start re-checking from then. Our own publishes also raise the
    // event, which the flags ignore.
    private void OnChanged(Task<AuthenticationState> state)
    {
        if (_looping || _publishing) return;
        _looping = true;
        _ = LoopAsync(_stop.Token);
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(Interval);
        try
        {
            while (await timer.WaitForNextTickAsync(ct))
                await RevalidateAsync();
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            // Never take the circuit down over a re-check; the next reconnect re-derives access anyway.
            _log.LogWarning(ex, "Session permission re-check stopped");
        }
    }

    /// <summary>Re-derives the current principal's access and publishes it if it changed. Returns whether it did.</summary>
    public async Task<bool> RevalidateAsync()
    {
        var state = await GetAuthenticationStateAsync();
        if (_refresher.Refresh(state.User) is not { } updated) return false;

        _publishing = true;
        try { SetAuthenticationState(Task.FromResult(new AuthenticationState(updated))); }
        finally { _publishing = false; }
        _log.LogInformation("Refreshed CaseBook permissions for an open session of {User}", updated.Identity?.Name);
        return true;
    }

    public void Dispose()
    {
        AuthenticationStateChanged -= OnChanged;
        _stop.Cancel();
        _stop.Dispose();
    }
}
