using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;

namespace IncidentManager.Application.Compliance;

/// <summary>
/// The gathered, verified contents of a compliance evidence bundle (C-01): an audit-chain segment for
/// a date range, the whole-chain integrity result, and the signed seals covering the range. Rendered
/// into the packaged files by <see cref="ComplianceBundlePack"/>.
/// </summary>
public sealed record ComplianceBundleModel(
    DateTimeOffset GeneratedAtUtc,
    string GeneratedByDisplay,
    string GeneratedByUserId,
    DateTimeOffset FromUtc,
    DateTimeOffset ToUtc,
    IReadOnlyList<AuditLogEntry> Segment,
    long TotalChainLength,
    long? SegmentFirstSequence,
    long? SegmentLastSequence,
    ChainVerificationResult ChainResult,
    long? ChainHeadSequence,
    string? ChainHeadHash,
    IReadOnlyList<SealLine> Seals,
    SealLine? CoveringSeal,
    string Algorithm,
    string KeyId,
    string PublicKeyPem);

/// <summary>A seal paired with the result of re-verifying it while building the bundle.</summary>
public sealed record SealLine(IntegritySeal Seal, bool SignatureValid, bool ChainMatches)
{
    public bool IsValid => SignatureValid && ChainMatches;
}

/// <summary>The packaged bundle: the zip bytes, a suggested file name, and the model behind it.</summary>
public sealed record ComplianceBundle(byte[] Content, string FileName, ComplianceBundleModel Model);
