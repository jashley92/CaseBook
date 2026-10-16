using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace IncidentManager.Infrastructure.Configuration;

/// <summary>
/// Reloads the configuration root — which re-runs every provider including the DB settings provider —
/// so a just-saved operational setting is reflected immediately in <c>IConfiguration</c> and re-bound
/// by <c>IOptionsMonitor</c> consumers.
/// </summary>
public sealed class ConfigurationReloader : ISettingsReloader
{
    private readonly IConfiguration _config;
    private readonly ILogger<ConfigurationReloader>? _log;

    public ConfigurationReloader(IConfiguration config, ILogger<ConfigurationReloader>? log = null)
    {
        _config = config;
        _log = log;
    }

    public void Reload() => ReloadAndReport();

    /// <summary>
    /// BUG-623: one reload at a time (under the settings provider's load gate), and the error returned is this reload's,
    /// read before another can start. It was a static shared by every reload, so with two at once a save could report the
    /// other's: "saved" when its own reload failed, or the reverse.
    /// </summary>
    public string? ReloadAndReport()
    {
        if (_config is not IConfigurationRoot root) return null;
        string? error;
        lock (DbSettingsConfigurationProvider.LoadGate)
        {
            root.Reload();
            error = root.Providers.OfType<DbSettingsConfigurationProvider>().Select(p => p.LoadError).FirstOrDefault(e => e is not null);
            _lastError = error;
        }
        // REV-60: a failed read keeps the values already loaded (BUG-29), so the change just saved isn't in effect. That
        // was said nowhere; it's logged, and the admin page says so (AdminSettingsService).
        if (error is not null)
            _log?.LogError("Couldn't reload the in-app settings from the database; the earlier values stay in effect: {Error}", error);
        return error;
    }

    private volatile string? _lastError;

    /// <summary>Why the last reload through this reloader couldn't read the settings, or null. A save uses what
    /// <see cref="ReloadAndReport"/> returned for its own reload instead.</summary>
    public string? LastError => _lastError;
}
