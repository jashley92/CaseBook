using IncidentManager.Application.Compliance;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Compliance;

/// <summary>
/// Reads the notification-deadline settings from the live configuration each time they are asked for, so an
/// administered change (which flows in via the DB settings provider) — including flipping the feature on/off —
/// is picked up without a restart. Keys: <c>Compliance:NotificationDeadlines:Enabled|StartBasis|
/// DefaultWindowHours|AtRiskThresholdPercent</c>. Mirrors <see cref="Sla.ConfigurationSlaTargetsProvider"/>.
/// </summary>
public sealed class ConfigurationNotificationDeadlineSettingsProvider : INotificationDeadlineSettingsProvider
{
    private const string Prefix = "Compliance:NotificationDeadlines:";

    private readonly IConfiguration _config;

    public ConfigurationNotificationDeadlineSettingsProvider(IConfiguration config) => _config = config;

    public NotificationDeadlineSettings Current
    {
        get
        {
            var enabled = _config.GetValue<bool?>(Prefix + "Enabled") ?? false;

            var basis = Enum.TryParse<NotificationStartBasis>(_config[Prefix + "StartBasis"], ignoreCase: true, out var b)
                ? b : NotificationStartBasis.Determination;

            var defaultWindow = _config.GetValue<int?>(Prefix + "DefaultWindowHours") ?? 72;
            if (defaultWindow <= 0) defaultWindow = 72;

            var pct = _config.GetValue<int?>(Prefix + "AtRiskThresholdPercent")
                      ?? NotificationDeadlinePolicy.DefaultAtRiskThresholdPercent;
            if (pct is <= 0 or > 100) pct = NotificationDeadlinePolicy.DefaultAtRiskThresholdPercent;

            return new NotificationDeadlineSettings(enabled, basis, defaultWindow, pct);
        }
    }
}
