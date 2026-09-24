namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Configuration for the periodic overdue after-action scan (E-03b), bound from the
/// <c>Notifications:OverdueScan</c> section. The scan itself is read-only; whether it actually emails
/// depends additionally on <c>Email:Enabled</c> (otherwise the reminder is logged, dev-safe).
/// </summary>
public sealed class OverdueScanOptions
{
    /// <summary>Whether the scan runs at all. Off by default — opt-in per deployment.</summary>
    public bool Enabled { get; set; }

    /// <summary>Hours between scans. Overdue reminders are not time-critical, so this is deliberately slow.</summary>
    public double IntervalHours { get; set; } = 24;

    /// <summary>PROD-03: widen a reminder that stays overdue (owner → incident commander → managers).</summary>
    public OverdueEscalationOptions Escalation { get; set; } = new();
}

/// <summary>
/// PROD-03 escalation chain for overdue items, bound from <c>Notifications:OverdueScan:Escalation</c>. Off by
/// default. Notifications only — the human-gated stance holds: nothing is reassigned or changed.
/// </summary>
public sealed class OverdueEscalationOptions
{
    public bool Enabled { get; set; }

    /// <summary>Hours overdue before the case's incident commander is told (0 disables the tier).</summary>
    public int IncidentCommanderAfterHours { get; set; } = 48;

    /// <summary>Hours overdue before managers are told (0 disables the tier).</summary>
    public int ManagersAfterHours { get; set; } = 120;
}
