namespace IncidentManager.Web.Services;

/// <summary>
/// Circuit-scoped mediator that lets any component ask the singleton <c>CommandPalette</c> (hosted once in
/// MainLayout) to open, without a direct reference between them. The top-bar search pill raises
/// <see cref="Open"/>; the palette subscribes to <see cref="OpenRequested"/>. Mirrors the event pattern used
/// by <see cref="TimeDisplay"/>. The palette still owns all search/keyboard behaviour — this only triggers it,
/// so there is one search surface, reachable by both mouse (the pill) and keyboard (Ctrl/⌘ K, "/").
/// </summary>
public sealed class CommandPaletteController
{
    /// <summary>Raised when something requests the palette be opened.</summary>
    public event Action? OpenRequested;

    /// <summary>Ask the hosted palette to open.</summary>
    public void Open() => OpenRequested?.Invoke();
}
