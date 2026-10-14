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
}

/// <summary>REV-60 / BUG-270: the one way a save that changed settings says they're saved but not in effect.</summary>
public static class SettingsReloads
{
    public static string NotInEffectMessage(string error) =>
        "Saved, but not in effect yet: CaseBook couldn't reload settings from the database " +
        $"({error}), so the earlier values still apply. Save again once the database is reachable, or restart the app.";

    /// <summary>Reloads, then throws <see cref="InvalidOperationException"/> when the reload couldn't read the settings.</summary>
    public static void ReloadOrThrow(this ISettingsReloader reloader)
    {
        reloader.Reload();
        if (reloader.LastError is { } error) throw new InvalidOperationException(NotInEffectMessage(error));
    }
}

/// <summary>BUG-245: the value the server's own configuration (appsettings, environment) gives a setting, without the
/// in-app changes; null when it sets none, so the catalog default applies.</summary>
public interface IServerSettingValues
{
    string? ValueOf(string key);
}
