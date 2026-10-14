namespace IncidentManager.Application.Integrity;

/// <summary>
/// BUG-332: raises a monitor's <c>Changed</c> event to each listener in turn. A listener is a banner on some circuit;
/// one that throws (a circuit going away) must neither reach the verifier that recorded the result nor stop the other
/// banners hearing about it.
/// </summary>
internal static class MonitorEvents
{
    public static void Raise(Action? changed)
    {
        if (changed is null) return;
        foreach (var listener in changed.GetInvocationList())
        {
            try { ((Action)listener)(); }
            catch (Exception) { /* a listener's failure is never the monitor's */ }
        }
    }
}
