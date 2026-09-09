using IncidentManager.Application.Sla;
using IncidentManager.Domain.Enums;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Sla;

/// <summary>
/// Reads the per-severity response-time targets from the live configuration each time they are asked for,
/// so an administered change (which flows in via the DB settings provider) is picked up without a restart.
/// Keys: <c>Sla:Containment:{Severity}</c>, <c>Sla:Resolution:{Severity}</c> (hours; blank/0 = no target)
/// and <c>Sla:AtRiskThresholdPercent</c>.
/// </summary>
public sealed class ConfigurationSlaTargetsProvider : ISlaTargetsProvider
{
    // Informational carries no SLA; only the four actionable severities have targets.
    private static readonly Severity[] Severities =
        { Severity.Low, Severity.Medium, Severity.High, Severity.Critical };

    private static readonly SlaClock[] Clocks = { SlaClock.Containment, SlaClock.Resolution };

    private readonly IConfiguration _config;

    public ConfigurationSlaTargetsProvider(IConfiguration config) => _config = config;

    public SlaTargets Current
    {
        get
        {
            var hours = new Dictionary<(SlaClock, Severity), int>();
            foreach (var clock in Clocks)
            foreach (var severity in Severities)
            {
                if (int.TryParse(_config[$"Sla:{clock}:{severity}"], out var h) && h > 0)
                    hours[(clock, severity)] = h;
            }

            var pct = _config.GetValue<int?>("Sla:AtRiskThresholdPercent")
                      ?? SlaPolicy.DefaultAtRiskThresholdPercent;
            if (pct is <= 0 or > 100) pct = SlaPolicy.DefaultAtRiskThresholdPercent;

            return new SlaTargets(hours, pct);
        }
    }
}
