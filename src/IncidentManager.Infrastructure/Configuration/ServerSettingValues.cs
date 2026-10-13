using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Configuration;

/// <summary>
/// BUG-245: what the server's own configuration (appsettings files, environment) gives a setting, leaving out the
/// values administered in CaseBook (the DB provider). It's what a setting runs on with no in-app change, and what
/// "Reset" goes back to, so Administration shows it rather than the catalog default the files may not use.
/// </summary>
public sealed class ServerSettingValues(IConfiguration config) : IServerSettingValues
{
    public string? ValueOf(string key)
    {
        if (config is not IConfigurationRoot root) return config[key];
        // Last provider wins, as in configuration itself.
        foreach (var provider in root.Providers.Reverse())
        {
            if (provider is DbSettingsConfigurationProvider) continue;
            if (provider.TryGet(key, out var value)) return value;
            // A list (Email:LegalDistribution) is stored as key:0, key:1, … : read back one item per line.
            var items = new List<string>();
            for (var i = 0; provider.TryGet($"{key}:{i}", out var item); i++)
                if (!string.IsNullOrWhiteSpace(item)) items.Add(item);
            if (items.Count > 0) return string.Join("\n", items);
        }
        return null;
    }
}
