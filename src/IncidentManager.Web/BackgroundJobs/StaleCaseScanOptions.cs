namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Configuration for the periodic stale-case nudge (PROD-38), bound from the <c>Notifications:StaleScan</c>
/// section. The scan is read-only; whether it actually emails depends additionally on <c>Email:Enabled</c>
/// (otherwise the nudge is logged, dev-safe).
/// </summary>
public sealed class StaleCaseScanOptions
{
    /// <summary>Whether the scan runs at all. Off by default — opt-in per deployment.</summary>
    public bool Enabled { get; set; }

    /// <summary>Hours between scans. Staleness is measured in days, so a slow cadence is fine. Default 12.</summary>
    public double IntervalHours { get; set; } = 12;

    /// <summary>Per-severity "days of quiet before a case counts as stale". 0 disables a severity's nudge.</summary>
    public StaleDaysOptions Days { get; set; } = new();
}

/// <summary>Per-severity staleness thresholds, in days. A Critical case going quiet matters far sooner than a
/// Low; 0 (the default for Informational) disables the nudge for that severity.</summary>
public sealed class StaleDaysOptions
{
    public int Critical { get; set; } = 2;
    public int High { get; set; } = 5;
    public int Medium { get; set; } = 10;
    public int Low { get; set; } = 21;
    public int Informational { get; set; } // 0 = never nudge Informational cases
}
