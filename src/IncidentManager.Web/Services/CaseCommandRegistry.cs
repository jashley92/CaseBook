namespace IncidentManager.Web.Services;

/// <summary>
/// Circuit-scoped registry that lets the open <c>CaseWorkspace</c> publish its available action verbs to the
/// <c>CommandPalette</c> (hosted once in MainLayout), without a direct reference between them (PROD-19). The
/// workspace registers a provider on load and clears it on teardown; the palette pulls the live list each time
/// it opens or the query changes. Mirrors the mediator pattern of <see cref="CommandPaletteController"/>.
///
/// All behaviour — permission gates, next-phase resolution, which modal to open — stays in CaseWorkspace; the
/// provider is a closure over its live state, so the palette always reflects the case as it currently is (e.g.
/// "Advance to Containment" retargets as the phase moves, "Assign to me" drops off once assigned). This class
/// only surfaces and invokes what the workspace already owns.
///
/// Registration is <em>owner-guarded</em>: MainLayout re-keys the routed page subtree on a time-zone change, so
/// a fresh CaseWorkspace can register before the outgoing one is disposed. A disposing instance therefore only
/// clears the registry when it is still the registered owner — otherwise its teardown would clobber the new
/// instance's registration and the palette would show no case actions.
/// </summary>
public sealed class CaseCommandRegistry
{
    private object? _owner;
    private Func<IReadOnlyList<CasePaletteAction>>? _provider;

    /// <summary>Publish the open case's action provider, recording <paramref name="owner"/> as its registrant.</summary>
    public void Set(object owner, Func<IReadOnlyList<CasePaletteAction>> provider)
    {
        _owner = owner;
        _provider = provider;
    }

    /// <summary>
    /// Withdraw the registration on teardown — but only when <paramref name="owner"/> is still the current
    /// registrant, so a disposing instance can't wipe a newer one's registration during a re-key remount.
    /// </summary>
    public void Clear(object owner)
    {
        if (ReferenceEquals(_owner, owner))
        {
            _owner = null;
            _provider = null;
        }
    }

    /// <summary>
    /// The open case's currently-available actions, computed fresh from its live state — or empty when no case
    /// workspace is open (or the viewer holds no permissions that yield an action).
    /// </summary>
    public IReadOnlyList<CasePaletteAction> Current() =>
        _provider?.Invoke() ?? Array.Empty<CasePaletteAction>();
}

/// <summary>A single case action verb offered in the command palette.</summary>
/// <param name="Label">The palette label, e.g. "Advance to Containment" or "Reclassify…".</param>
/// <param name="Icon">A Bootstrap-icon class, e.g. "bi-arrow-right-circle".</param>
/// <param name="Run">Executes the action against the live workspace (opens a modal or applies a one-click change).</param>
public sealed record CasePaletteAction(string Label, string Icon, Func<Task> Run);
