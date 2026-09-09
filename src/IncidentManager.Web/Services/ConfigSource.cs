using IncidentManager.Infrastructure.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.CommandLine;
using Microsoft.Extensions.Configuration.EnvironmentVariables;
using Microsoft.Extensions.Configuration.Memory;

namespace IncidentManager.Web.Services;

/// <summary>The effective value of a configuration key and which provider supplied it.</summary>
public sealed record ConfigResolution(string? Value, string Source);

/// <summary>
/// Resolves where a configuration key's effective value actually comes from by walking the live
/// provider chain — the transparency behind the A-07 config-source map. Providers are consulted in
/// order and the last one holding the key wins, mirroring how <c>IConfiguration</c> resolves it, so
/// the answer reflects the real runtime precedence (DB override &gt; appsettings &gt; default).
/// </summary>
public static class ConfigSource
{
    public static ConfigResolution Resolve(IConfiguration config, string key)
    {
        string? value = null;
        string source = "Default";

        if (config is IConfigurationRoot root)
        {
            foreach (var p in root.Providers)
            {
                if (p.TryGet(key, out var v))
                {
                    value = v;
                    source = Label(p);
                }
            }
        }
        else
        {
            value = config[key];
            source = value is null ? "Default" : "Configuration";
        }

        return new ConfigResolution(value, value is null ? "Default (unset)" : source);
    }

    private static string Label(IConfigurationProvider p) => p switch
    {
        DbSettingsConfigurationProvider => "Database (audited)",
        EnvironmentVariablesConfigurationProvider => "Environment",
        CommandLineConfigurationProvider => "Command line",
        FileConfigurationProvider f => Path.GetFileName(f.Source.Path ?? "file"),
        MemoryConfigurationProvider => "Memory",
        _ => p.GetType().Name.Replace("ConfigurationProvider", "")
    };
}
