namespace IncidentManager.Application.Admin;

/// <summary>
/// The built-in per-jurisdiction notification-deadline rules (PROD-07) seeded on first run — a minimal,
/// NY-insurer-oriented baseline. After seeding these are admin-managed reference data (relabel / retime /
/// archive / add). Codes are keyed to the same jurisdiction space as
/// <see cref="IncidentManager.Domain.Entities.DataElement.NotificationJurisdictions"/>. Everything not listed
/// falls back to the configured default window, so the set stays small even with 50 states.
/// </summary>
public static class NotificationRuleCatalog
{
    public sealed record Seed(string Code, string Label, int WindowHours);

    public static readonly IReadOnlyList<Seed> Defaults =
    [
        new("NY", "New York (NYDFS Part 500)", 72),
        new("US", "Federal", 72),
    ];
}
