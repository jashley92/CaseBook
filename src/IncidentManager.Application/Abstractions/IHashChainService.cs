using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;

namespace IncidentManager.Application.Abstractions;

/// <summary>Outcome of verifying an audit chain; identifies the first broken link if any.</summary>
public sealed record ChainVerificationResult(bool IsValid, long? FirstBrokenSequence, string? Detail)
{
    public static ChainVerificationResult Valid { get; } = new(true, null, null);
    public static ChainVerificationResult Broken(long sequence, string detail) => new(false, sequence, detail);
}

/// <summary>
/// Cryptographic tamper-evidence primitives. Pure and provider-independent so the same
/// mechanism works on the dev database and in production, and is fully unit-testable.
/// </summary>
public interface IHashChainService
{
    /// <summary>Lower-case hex SHA-256 of the supplied content.</summary>
    string Hash(string content);

    /// <summary>Computes the point-in-time row hash for a hashable entity.</summary>
    string ComputeRowHash(IHashableEntity entity);

    /// <summary>
    /// Links a new audit entry onto the chain, assigning its sequence, previous-hash and
    /// entry-hash based on the current head (<paramref name="previous"/> is null for genesis).
    /// </summary>
    void ChainAppend(AuditLogEntry entry, AuditLogEntry? previous);

    /// <summary>
    /// Verifies an ordered audit chain end-to-end, detecting altered records, broken links,
    /// and sequence gaps (insertions/deletions).
    /// </summary>
    ChainVerificationResult VerifyChain(IReadOnlyList<AuditLogEntry> orderedEntries);
}
