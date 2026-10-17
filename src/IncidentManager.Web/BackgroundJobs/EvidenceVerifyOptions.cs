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
    /// Hours between re-verification runs (default daily). Each run re-hashes its share of the stored evidence files
    /// (<see cref="PassDays"/>) — unlike the audit-chain verify, which runs every few minutes.
    /// </summary>
    public double IntervalHours { get; set; } = 24;

    /// <summary>
    /// PROD-53: every stored file is re-hashed at least once in this many days. Each run checks one share of the files
    /// (<see cref="Application.Integrity.EvidenceIntegrityVerifier.Shares"/>), so a large store isn't read end to end every
    /// run. 1 checks every file every run.
    /// </summary>
    public int PassDays { get; set; } = 7;
}
