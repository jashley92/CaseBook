using IncidentManager.Application.Cases;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Routing;

namespace IncidentManager.Web.Services;

/// <summary>
/// RD-21: the circuit's view of the user's open-case tabs, shared by the tab strip (in MainLayout), the case workspace
/// (which opens a tab and says where in the case you are) and the beside pane. The list itself is stored per user by
/// <see cref="CaseTabsService"/>, so it comes back at the next sign-in; where you were in each case (its view, lens and
/// open drawer, as the URL carries them) is kept for the session, so going back to a tab lands where you left it.
/// </summary>
public sealed class CaseTabsState : IDisposable
{
    private readonly CaseTabsService _svc;
    private readonly NavigationManager _nav;
    private readonly Dictionary<Guid, string> _lastUrl = new();
    private bool _loaded;

    // BUG-509: the address the workspace last wrote with replaceState, which Nav.Uri never sees, and the navigation it
    // was written under. Until the next navigation it is where the browser is.
    private (Guid CaseId, string Url, string NavUri, int Navigation)? _written;
    private int _navigations;

    public CaseTabsState(CaseTabsService svc, NavigationManager nav)
    {
        _svc = svc;
        _nav = nav;
        _nav.LocationChanged += OnLocationChanged;
    }

    private void OnLocationChanged(object? sender, LocationChangedEventArgs e) => _navigations++;

    public void Dispose() => _nav.LocationChanged -= OnLocationChanged;

    public IReadOnlyList<CaseTab> Tabs { get; private set; } = [];

    /// <summary>The case open beside the current page (split view), if any.</summary>
    public Guid? Beside { get; private set; }

    public event Action? Changed;

    public async Task EnsureLoadedAsync()
    {
        if (_loaded) return;
        _loaded = true;
        await RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try { Tabs = await _svc.ListAsync(); }
        catch (Exception ex) when (ex is InvalidOperationException or Microsoft.EntityFrameworkCore.DbUpdateException
                                       or System.Data.Common.DbException or TimeoutException) { /* keep the last list (BUG-702) */ }
        Changed?.Invoke();
    }

    /// <summary>The workspace opened a case: make it a tab (or bring it forward).</summary>
    public async Task OpenedAsync(Guid caseId)
    {
        _loaded = true;
        await _svc.OpenAsync(caseId);
        if (Beside == caseId) Beside = null;   // it's in front now
        await RefreshAsync();
    }

    public async Task CloseAsync(Guid caseId)
    {
        await _svc.CloseAsync(caseId);
        _lastUrl.Remove(caseId);
        if (Beside == caseId) Beside = null;
        await RefreshAsync();
    }

    /// <summary>Where in the case the user is (the workspace's URL), for coming back to the tab.</summary>
    public void Remember(Guid caseId, string relativeUrl)
    {
        _lastUrl[caseId] = relativeUrl;
        _written = (caseId, relativeUrl, _nav.Uri, _navigations);
    }

    /// <summary>BUG-509: for a workspace rebuilt in place (MainLayout re-keys the page on a time-mode change), the address
    /// the browser is at, which the router doesn't know: the one last written for this case, if nothing has navigated
    /// since. Null otherwise (a first load, a reload, Back or Forward, a link), when the router's address is the real one.
    /// The router's address is checked too, as the router builds the page before this hears of a navigation.</summary>
    public string? WrittenUrlFor(Guid caseId) =>
        _written is { } w && w.CaseId == caseId && w.Navigation == _navigations && w.NavUri == _nav.Uri ? w.Url : null;

    /// <summary>BUG-509: the page is rebuilt for its first load (the circuit's display zone arriving), so the router's
    /// address, with its deep link, is the one to open.</summary>
    public void ForgetWritten() => _written = null;

    public string UrlFor(Guid caseId) => _lastUrl.TryGetValue(caseId, out var u) ? u : $"cases/{caseId}";

    public void SetBeside(Guid? caseId)
    {
        Beside = caseId;
        Changed?.Invoke();
    }
}
