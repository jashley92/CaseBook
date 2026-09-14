namespace IncidentManager.Application.Compliance;

/// <summary>
/// Supplies the currently-administered <see cref="NotificationDeadlineSettings"/> (the
/// <c>Compliance:NotificationDeadlines:*</c> group). Implemented over the live configuration (appsettings
/// default + DB override), so an admin change — including flipping the feature on/off — takes effect without
/// a restart. Mirrors <see cref="Sla.ISlaTargetsProvider"/>.
/// </summary>
public interface INotificationDeadlineSettingsProvider
{
    NotificationDeadlineSettings Current { get; }
}
