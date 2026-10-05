using IncidentManager.Application.Cases;

namespace IncidentManager.Web.Services;

/// <summary>
/// RD-21: the circuit's view of the user's open-case tabs, shared by the tab strip (in MainLayout), the case workspace
/// (which opens a tab and says where in the case you are) and the beside pane. The list itself is stored per user by
/// <see cref="CaseTabsService"/>, so it comes back at the next sign-in; where you were in each case (its view, lens and
/// open drawer, as the URL carries them) is kept for the session, so going back to a tab lands where you left it.
/// </summary>
public sealed class CaseTabsState
{
    private readonly CaseTabsService _svc;
    private readonly Dictionary<Guid, string> _lastUrl = new();
    private bool _loaded;

    public CaseTabsState(CaseTabsService svc) => _svc = svc;

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
        catch (Exception ex) when (ex is InvalidOperationException or Microsoft.EntityFrameworkCore.DbUpdateException) { /* keep the last list */ }
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
    public void Remember(Guid caseId, string relativeUrl) => _lastUrl[caseId] = relativeUrl;

    public string UrlFor(Guid caseId) => _lastUrl.TryGetValue(caseId, out var u) ? u : $"cases/{caseId}";

    public void SetBeside(Guid? caseId)
    {
        Beside = caseId;
        Changed?.Invoke();
    }
}
