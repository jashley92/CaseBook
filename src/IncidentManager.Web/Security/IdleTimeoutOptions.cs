namespace IncidentManager.Web.Security;

/// <summary>
/// Bound to the <c>Security</c> configuration section (F-15). The value is administered in-app
/// (audited, DB-backed) and layered over appsettings, so a fresh circuit reads it via
/// <c>IOptionsSnapshot</c> and an admin change applies to sessions started afterward without a restart.
/// </summary>
public sealed class IdleTimeoutOptions
{
    /// <summary>Minutes of inactivity before the session is locked. 0 (or negative) disables the app-level timeout.</summary>
    public int IdleTimeoutMinutes { get; set; } = 15;
}
