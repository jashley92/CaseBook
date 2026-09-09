namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Configuration for the periodic audit-chain verify/seal background job, bound from the
/// <c>Integrity:AutoSeal</c> configuration section.
/// </summary>
public sealed class AutoSealOptions
{
    /// <summary>Whether the background job runs at all.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Hours between signed seals. Verification and tamper-alarming run continuously and independently
    /// (about every 10 minutes), so this interval only bounds how much recent history is not yet covered
    /// by a seal — not detection latency.
    /// </summary>
    public double IntervalHours { get; set; } = 6;
}
