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

    public void Reload()
    {
        if (_config is IConfigurationRoot root)
            root.Reload();
        // REV-60: a failed read keeps the values already loaded (BUG-29), so the change just saved isn't in effect. That
        // was said nowhere; it's logged, and the admin page says so (AdminSettingsService).
        if (LastError is { } error)
            _log?.LogError("Couldn't reload the in-app settings from the database; the earlier values stay in effect: {Error}", error);
    }

    public string? LastError => DbSettingsConfigurationProvider.LastLoadError;
}
