using System.Security.Cryptography;
using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// SHA-256 hash-chain implementation. The genesis entry links against an empty previous hash;
/// each subsequent entry hashes its canonical content together with the prior entry's hash,
/// forming a chain where any alteration, insertion, or deletion is detectable. With the chain key on
/// (F-25), new entries are hashed with HMAC-SHA256 under it instead, so database access alone can't
/// produce a chain that verifies; entries written before keep their plain hash.
/// </summary>
public sealed class HashChainService : IHashChainService
{
    private const string GenesisPrevHash = "";
    private readonly IChainKeyring _keys;

    public HashChainService(IChainKeyring? keys = null) => _keys = keys ?? NoChainKeys.Instance;

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
        entry.HashKeyId = _keys.CurrentKeyId;
        entry.EntryHash = ComputeEntryHash(entry)!;
    }

    public ChainVerificationResult VerifyChain(IReadOnlyList<AuditLogEntry> orderedEntries)
    {
        var prevHash = GenesisPrevHash;
        long expectedSequence = 1;
        long? firstKeyed = null;

        foreach (var entry in orderedEntries)
        {
            if (entry.Sequence != expectedSequence)
                return ChainVerificationResult.Broken(entry.Sequence,
                    $"Sequence gap: expected {expectedSequence}, found {entry.Sequence} (entry inserted or removed).");

            if (entry.PrevHash != prevHash)
                return ChainVerificationResult.Broken(entry.Sequence,
                    "Previous-hash link doesn't match the prior entry's hash.");

            // F-25: once the chain is keyed it stays keyed, so an entry can't be rewritten under the plain hash.
            if (entry.HashKeyId is null && firstKeyed is { } k)
                return ChainVerificationResult.Broken(entry.Sequence,
                    $"Entry has the plain hash, but the chain has been keyed since entry #{k}. It was rewritten without the chain key, or the chain key was turned off.");
            if (entry.HashKeyId is { } keyId)
            {
                firstKeyed ??= entry.Sequence;
                if (_keys.Key(keyId) is null)
                    return ChainVerificationResult.Broken(entry.Sequence,
                        $"Entry was hashed with chain key {keyId}, which this server doesn't hold. Add it to the chain key configuration (current or retired) to check it.");
            }

            var recomputed = ComputeEntryHash(entry);
            if (entry.EntryHash != recomputed)
                return ChainVerificationResult.Broken(entry.Sequence,
                    "Entry hash doesn't match its content. This record was altered after it was written.");

            prevHash = entry.EntryHash;
            expectedSequence++;
        }

        return ChainVerificationResult.Valid;
    }

    // Plain SHA-256, or HMAC-SHA256 under the key the entry names. Null when that key isn't held.
    private string? ComputeEntryHash(AuditLogEntry entry)
    {
        var input = entry.BuildCanonicalContent() + "|" + entry.PrevHash;
        if (entry.HashKeyId is not { } keyId) return Hash(input);
        return _keys.Key(keyId) is { } key
            ? Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(input))).ToLowerInvariant()
            : null;
    }
}
