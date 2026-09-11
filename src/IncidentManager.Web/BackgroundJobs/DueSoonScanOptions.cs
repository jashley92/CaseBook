namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Configuration for the periodic due-soon after-action scan (E-03d), bound from the
/// <c>Notifications:DueSoonScan</c> section. The scan is read-only; whether it actually emails depends
/// additionally on <c>Email:Enabled</c> (otherwise the reminder is logged, dev-safe).
/// </summary>
public sealed class DueSoonScanOptions
{
    /// <summary>Whether the scan runs at all. Off by default — opt-in per deployment.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// How far ahead of an item's due date to remind, in hours (default 24 = "due within a day"). An item is
    /// reminded once as it enters this window; it then gets a distinct overdue reminder later if it lapses.
    /// </summary>
    public double LeadHours { get; set; } = 24;

    /// <summary>
    /// Hours between scans. Should be no larger than the lead window, so an item can't slip from "future"
    /// straight to "overdue" between passes without a due-soon reminder. Default 6.
    /// </summary>
    public double IntervalHours { get; set; } = 6;
}
