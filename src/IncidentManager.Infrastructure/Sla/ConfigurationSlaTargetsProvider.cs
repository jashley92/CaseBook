using IncidentManager.Application.Sla;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Sla;

/// <summary>
/// Reads the per-severity response-time targets from the live configuration each time they are asked for,
/// so an administered change (which flows in via the DB settings provider) is picked up without a restart.
/// Keys: <c>Sla:Containment:{Severity}</c>, <c>Sla:Resolution:{Severity}</c> (hours; blank, 0 or over a year = no target)
/// and <c>Sla:AtRiskThresholdPercent</c>.
/// </summary>
public sealed class ConfigurationSlaTargetsProvider : ISlaTargetsProvider
{
    private readonly IConfiguration _config;

    public ConfigurationSlaTargetsProvider(IConfiguration config) => _config = config;

    // BUG-322: built by the same rule the target history uses for past moments.
    public SlaTargets Current => SlaTargetSettings.From(key => _config[key]);
}
