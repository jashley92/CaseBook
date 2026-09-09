using System.Security.Cryptography;
using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// SHA-256 hash-chain implementation. The genesis entry links against an empty previous hash;
/// each subsequent entry hashes its canonical content together with the prior entry's hash,
/// forming a chain where any alteration, insertion, or deletion is detectable.
/// </summary>
public sealed class HashChainService : IHashChainService
{
    private const string GenesisPrevHash = "";

    public string Hash(string content)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public string ComputeRowHash(IHashableEntity entity) => Hash(entity.BuildCanonicalContent());

    public void ChainAppend(AuditLogEntry entry, AuditLogEntry? previous)
    {
        entry.Sequence = (previous?.Sequence ?? 0) + 1;
        entry.PrevHash = previous?.EntryHash ?? GenesisPrevHash;
        entry.EntryHash = ComputeEntryHash(entry);
    }

    public ChainVerificationResult VerifyChain(IReadOnlyList<AuditLogEntry> orderedEntries)
    {
        var prevHash = GenesisPrevHash;
        long expectedSequence = 1;

        foreach (var entry in orderedEntries)
        {
            if (entry.Sequence != expectedSequence)
                return ChainVerificationResult.Broken(entry.Sequence,
                    $"Sequence gap: expected {expectedSequence}, found {entry.Sequence} (entry inserted or removed).");

            if (entry.PrevHash != prevHash)
                return ChainVerificationResult.Broken(entry.Sequence,
                    "Previous-hash link does not match the prior entry's hash.");

            var recomputed = ComputeEntryHash(entry);
            if (entry.EntryHash != recomputed)
                return ChainVerificationResult.Broken(entry.Sequence,
                    "Entry hash does not match its content — this record was altered after it was written.");

            prevHash = entry.EntryHash;
            expectedSequence++;
        }

        return ChainVerificationResult.Valid;
    }

    private string ComputeEntryHash(AuditLogEntry entry) =>
        Hash(entry.BuildCanonicalContent() + "|" + entry.PrevHash);
}
