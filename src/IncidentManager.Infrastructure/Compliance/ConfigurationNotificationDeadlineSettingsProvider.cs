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

            // BUG-592: by name only; "5" was read as an undefined basis, and no deadline clock started.
            var basis = Domain.Common.EnumNames.TryParse<NotificationStartBasis>(_config[Prefix + "StartBasis"], out var b, ignoreCase: true)
                ? b : NotificationStartBasis.Determination;

            var defaultWindow = _config.GetValue<int?>(Prefix + "DefaultWindowHours") ?? 72;
            // REV-48: within the rules' own limits. A huge value from the file put every deadline past year 9999 and threw in
            // each calculation (dashboards, case lists, the scanner).
            if (defaultWindow is <= 0 or > Application.Admin.NotificationRuleService.MaxWindowHours) defaultWindow = 72;

            var pct = _config.GetValue<int?>(Prefix + "AtRiskThresholdPercent")
                      ?? NotificationDeadlinePolicy.DefaultAtRiskThresholdPercent;
            if (pct is <= 0 or > 100) pct = NotificationDeadlinePolicy.DefaultAtRiskThresholdPercent;

            return new NotificationDeadlineSettings(enabled, basis, defaultWindow, pct);
        }
    }
}
