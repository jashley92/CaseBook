using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A single operational setting administered in the web console rather than in server-side
/// <c>appsettings.json</c>. Persisted, hash-chained and audited like any other mutation, so every
/// configuration change is tamper-evident and attributable to an administrator.
///
/// Only the whitelisted operational subset lives here (see <c>SettingsCatalog</c>); security- and
/// infrastructure-sensitive settings (auth mode, connection strings, signing keys, storage paths,
/// AD group→role mapping) stay in server-side configuration and are never written to this table.
/// </summary>
public class AppSetting : Entity, IHashableEntity
{
    /// <summary>Configuration key path (e.g. "Email:From"), matching the IConfiguration key it overrides.</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>The value as a string; typed interpretation is defined by the settings catalog.</summary>
    public string? Value { get; set; }

    public DateTimeOffset UpdatedAtUtc { get; set; }
    public string UpdatedBy { get; set; } = string.Empty;

    public string? RowHash { get; set; }

    /// <summary>
    /// Binds the key, value and who/when so a stored setting cannot be silently swapped without
    /// invalidating its row hash and breaking the audit chain.
    /// </summary>
    public string BuildCanonicalContent() =>
        string.Join('|', Key, Value ?? "", UpdatedAtUtc.ToString("o"), UpdatedBy);
}
