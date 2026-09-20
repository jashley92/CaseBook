namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Configuration for the periodic consolidated-work-digest scan (PROD-39), bound from the
/// <c>Notifications:DigestScan</c> section. The scan is read-only and honours each user's opt-in cadence; it
/// is the master switch (off by default) — a user only receives a digest when this is on <b>and</b> they've
/// chosen Daily or Weekly. Delivery still requires <c>Email:Enabled</c> (otherwise the digest is logged).
/// </summary>
public sealed class DigestScanOptions
{
    /// <summary>Whether the digest feature runs at all. Off by default — opt-in per deployment.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Hours between scans. A digest sends once per period (day/week) regardless; a small interval just means
    /// it goes out promptly once the period rolls over or the user's first items appear. Default 1.
    /// </summary>
    public double IntervalHours { get; set; } = 1;
}
