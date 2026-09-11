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
}
