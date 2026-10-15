using System.Globalization;

namespace IncidentManager.Web.Services;

/// <summary>
/// BUG-547: the app's one culture, pinned at startup so the server account's culture (a Buddhist or Hijri calendar, a
/// comma decimal) can't change dates and numbers anywhere. Invariant rather than en-US: the UI is English either way,
/// the per-site fixes (BUG-511/529-531/537) and their tests already format invariant, and en-US's data shifts between
/// ICU versions (a narrow no-break space before AM/PM) and honours the account's regional overrides.
/// </summary>
public static class AppCulture
{
    public static CultureInfo Culture => CultureInfo.InvariantCulture;

    /// <summary>
    /// Sets the culture for this thread and the default for every thread that hasn't set its own: thread-pool work,
    /// hosted services, request threads and the Blazor circuits created from them (nothing in the app sets one).
    /// </summary>
    public static void Pin()
    {
        CultureInfo.DefaultThreadCurrentCulture = Culture;
        CultureInfo.DefaultThreadCurrentUICulture = Culture;
        CultureInfo.CurrentCulture = Culture;
        CultureInfo.CurrentUICulture = Culture;
    }
}
