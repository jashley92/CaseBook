namespace IncidentManager.Application.Security;

/// <summary>
/// The client-side timing derived from the administered idle-timeout setting (F-15): whether the
/// app-level timeout is active and, if so, how long a circuit may sit idle before it is locked and how
/// far ahead of that deadline the "still there?" warning appears. Milliseconds, ready to hand to the
/// browser timer.
/// </summary>
public sealed record IdleTimeoutPlan(bool Enabled, int IdleMs, int WarnMs)
{
    public static readonly IdleTimeoutPlan Disabled = new(false, 0, 0);
}

/// <summary>
/// Turns the administered <c>Security:IdleTimeoutMinutes</c> value into a concrete <see cref="IdleTimeoutPlan"/>.
/// Pure and side-effect free so the behaviour is unit-tested independently of the Blazor/JS plumbing.
/// </summary>
public static class IdleTimeoutPolicy
{
    /// <summary>How long the inactivity warning is shown before the session is actually locked.</summary>
    public const int WarningSeconds = 60;

    /// <summary>
    /// Computes the timing plan for a given timeout in minutes. Zero or negative disables the app-level
    /// timeout (the deployment then relies on OS/AD screen-lock alone). The warning window is
    /// <see cref="WarningSeconds"/> but never more than half the total, so a very short timeout still
    /// leaves a real idle period before the warning shows.
    /// </summary>
    public static IdleTimeoutPlan Compute(int minutes)
    {
        if (minutes <= 0) return IdleTimeoutPlan.Disabled;

        var idleMs = minutes * 60_000;
        var warnMs = Math.Min(WarningSeconds * 1_000, idleMs / 2);
        return new IdleTimeoutPlan(true, idleMs, warnMs);
    }
}
