using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Severities;

/// <summary>
/// Reads the per-severity display label from live configuration each time it is asked for, so an
/// administered rename (which flows in via the DB settings provider) is picked up without a restart.
/// Key: <c>Severity:Label:{Severity}</c>. Falls back to the canonical enum name when unset or blank.
/// </summary>
public sealed class ConfigurationSeverityLabels : ISeverityLabels
{
    private readonly IConfiguration _config;

    public ConfigurationSeverityLabels(IConfiguration config) => _config = config;

    public string For(Severity severity)
    {
        var label = _config[$"Severity:Label:{severity}"];
        return string.IsNullOrWhiteSpace(label) ? severity.ToString() : label.Trim();
    }
}
