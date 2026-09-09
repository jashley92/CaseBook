namespace IncidentManager.Application.Sla;

/// <summary>
/// Supplies the currently-administered <see cref="SlaTargets"/>. Implemented over the live configuration
/// (appsettings default + DB override), so an admin change to a target takes effect without a restart.
/// </summary>
public interface ISlaTargetsProvider
{
    /// <summary>The effective targets right now.</summary>
    SlaTargets Current { get; }
}
