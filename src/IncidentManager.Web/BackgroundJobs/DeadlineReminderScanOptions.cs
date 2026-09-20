namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Configuration for the periodic regulatory notification-deadline scan (PROD-37), bound from the
/// <c>Notifications:DeadlineScan</c> section. The scan is read-only and additionally requires the deadline
/// clock itself to be on (<c>Compliance:NotificationDeadlines:Enabled</c>) and — to actually deliver —
/// <c>Email:Enabled</c> (otherwise the reminder is logged, dev-safe).
/// </summary>
public sealed class DeadlineReminderScanOptions
{
    /// <summary>Whether the scan runs at all. Off by default — opt-in per deployment.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Hours between scans. A regulatory deadline is time-critical (a 72-hour window can move from on-track to
    /// at-risk to breached inside a day), so this is faster than the after-action scans. Default 1.
    /// </summary>
    public double IntervalHours { get; set; } = 1;
}
