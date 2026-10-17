namespace IncidentManager.Application.Integrity;

/// <summary>How a piece of evidence failed at-rest re-verification (F-17).</summary>
public enum EvidenceDriftKind
{
    /// <summary>The stored bytes are present but their SHA-256 no longer matches the recorded hash
    /// (bit-rot, or a substitution of the file content under the store).</summary>
    HashMismatch,

    /// <summary>The recorded file is gone from the evidence store (deleted or moved out of band).</summary>
    Missing,

    /// <summary>The file exists but could not be read/hashed (permissions, IO error, path rejected).</summary>
    Unreadable
}

/// <summary>
/// One evidence item that failed at-rest re-verification. Carries only ids/labels — the SIEM event
/// derived from it never includes the filename or any case content.
/// </summary>
public sealed record EvidenceDrift(
    Guid EvidenceId,
    Guid CaseId,
    string? CaseNumber,
    string OriginalFileName,
    string ExpectedSha256,
    string? ActualSha256,
    EvidenceDriftKind Kind,
    string Detail);

/// <summary>
/// Outcome of one at-rest re-verification run over the evidence store (F-17): how many items were
/// checked and which, if any, drifted from their recorded SHA-256. PROD-53: a run may check one share of the files
/// (<see cref="CheckedIds"/>, out of <see cref="KnownIds"/>, every item in the store); null for a run over every file.
/// </summary>
public sealed record EvidenceVerificationResult(
    int CheckedCount,
    IReadOnlyList<EvidenceDrift> Drifts,
    DateTimeOffset CheckedAtUtc,
    IReadOnlySet<Guid>? CheckedIds = null,
    IReadOnlySet<Guid>? KnownIds = null)
{
    /// <summary>True when every checked item's bytes still matched its recorded hash.</summary>
    public bool IsClean => Drifts.Count == 0;

    /// <summary>Whether this run checked every file in the store.</summary>
    public bool CoversEveryFile => CheckedIds is null;

    /// <summary>How many evidence items the store holds (all of them checked, for a run over every file).</summary>
    public int TotalCount => KnownIds?.Count ?? CheckedCount;
}
