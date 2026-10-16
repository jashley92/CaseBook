namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Signals that administered operational settings changed so any layered configuration (the DB
/// settings provider) can re-read them and consumers bound via <c>IOptionsMonitor</c> observe the
/// new values without a restart. Implemented in Infrastructure over <c>IConfigurationRoot.Reload()</c>.
/// </summary>
public interface ISettingsReloader
{
    void Reload();

    /// <summary>REV-60: why the last reload couldn't read the in-app settings (the earlier values stay in effect), or null.</summary>
    string? LastError => null;

    /// <summary>
    /// BUG-623: reloads, and returns why this reload couldn't read the in-app settings (null when it could). A save uses
    /// this rather than <see cref="Reload"/> then <see cref="LastError"/>, which with two reloads at once can be the other's.
    /// </summary>
    string? ReloadAndReport()
    {
        Reload();
        return LastError;
    }
}

/// <summary>REV-60 / BUG-270: the one way a save that changed settings says they're saved but not in effect.</summary>
public static class SettingsReloads
{
    public static string NotInEffectMessage(string error) =>
        "Saved, but not in effect yet: CaseBook couldn't reload settings from the database " +
        $"({error}), so the earlier values still apply. Save again once the database is reachable, or restart the app.";

    /// <summary>Reloads, then throws <see cref="SettingsNotInEffectException"/> when the reload couldn't read the settings.</summary>
    public static void ReloadOrThrow(this ISettingsReloader reloader) => ThrowIfNotInEffect(reloader.ReloadAndReport());

    /// <summary>BUG-526: throws <see cref="SettingsNotInEffectException"/>, carrying <paramref name="newStamp"/>, when the
    /// reload couldn't read the settings. BUG-623: <paramref name="reloadError"/> is what that reload's
    /// <see cref="ISettingsReloader.ReloadAndReport"/> returned.</summary>
    public static void ThrowIfNotInEffect(string? reloadError, string? newStamp = null)
    {
        if (reloadError is { } error) throw new SettingsNotInEffectException(error, newStamp);
    }
}

/// <summary>
/// BUG-526: the change is saved (and audited), but the settings reload after it couldn't read the settings, so the earlier
/// values still apply. An <see cref="InvalidOperationException"/>, so a catch of that still shows the message; a page that
/// catches this treats the save as done (moves its stamps on, carries on with the rest, reloads) and then shows the message
/// as a warning. Treated as nothing saved, the retry was refused as a stale edit.
/// </summary>
public sealed class SettingsNotInEffectException(string reloadError, string? newStamp = null)
    : InvalidOperationException(SettingsReloads.NotInEffectMessage(reloadError))
{
    /// <summary>Why the reload couldn't read the settings.</summary>
    public string ReloadError { get; } = reloadError;

    /// <summary>The saved item's stamp after the save, for a method that returns one (a taxonomy order), else null.</summary>
    public string? NewStamp { get; } = newStamp;
}

/// <summary>BUG-245: the value the server's own configuration (appsettings, environment) gives a setting, without the
/// in-app changes; null when it sets none, so the catalog default applies.</summary>
public interface IServerSettingValues
{
    string? ValueOf(string key);
}
