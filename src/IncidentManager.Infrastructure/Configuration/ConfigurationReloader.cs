using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Configuration;

/// <summary>
/// Reloads the configuration root — which re-runs every provider including the DB settings provider —
/// so a just-saved operational setting is reflected immediately in <c>IConfiguration</c> and re-bound
/// by <c>IOptionsMonitor</c> consumers.
/// </summary>
public sealed class ConfigurationReloader : ISettingsReloader
{
    private readonly IConfiguration _config;

    public ConfigurationReloader(IConfiguration config) => _config = config;

    public void Reload()
    {
        if (_config is IConfigurationRoot root)
            root.Reload();
    }
}
