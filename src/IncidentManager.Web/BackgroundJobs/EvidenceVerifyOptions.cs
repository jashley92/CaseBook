namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Configuration for the periodic evidence-at-rest re-verification job (F-17), bound from the
/// <c>Integrity:EvidenceVerify</c> configuration section.
/// </summary>
public sealed class EvidenceVerifyOptions
{
    /// <summary>Whether the background job runs at all. Off by default — re-hashing every stored file is
    /// I/O-heavy, so it is opt-in per deployment.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Hours between full re-verification passes. A pass re-hashes every stored evidence file, so this is
    /// deliberately slow (default daily) — unlike the audit-chain verify, which runs every few minutes.
    /// </summary>
    public double IntervalHours { get; set; } = 24;
}
