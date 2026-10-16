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

    // BUG-67: the latest entry this server hashed with the chain key. The plain-after-keyed rule needs a keyed entry
    // to survive, so someone with database access could otherwise downgrade every keyed entry not yet under a seal;
    // while this server runs, the one it last keyed must still be keyed.
    private long _lastKeyedSequence;

    public string Hash(string content)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    // BUG-24: new row hashes are over the escaped canonical and say which format; older ones are checked as written.
    // BUG-316: format 3 adds the fields the earlier formats left out. C18: format 4 the stored values they still did.
    public string ComputeRowHash(IHashableEntity entity) =>
        Canonical.PrefixOf(Canonical.CurrentFormat) + Hash(Canonical.InFormat(Canonical.CurrentFormat, entity.BuildCanonicalContent));

    public bool RowHashMatches(IHashableEntity entity, string stored)
    {
        var format = Canonical.FormatOf(stored);
        return string.Equals(Canonical.PrefixOf(format) + Hash(Canonical.InFormat(format, entity.BuildCanonicalContent)), stored,
            StringComparison.OrdinalIgnoreCase);
    }

    public void ChainAppend(AuditLogEntry entry, AuditLogEntry? previous)
    {
        entry.Sequence = (previous?.Sequence ?? 0) + 1;
        entry.PrevHash = previous?.EntryHash ?? GenesisPrevHash;
        entry.HashKeyId = _keys.CurrentKeyId;
        entry.Format = AuditLogEntry.CurrentFormat;   // BUG-184
        entry.EntryHash = ComputeEntryHash(entry)!;
        if (entry.HashKeyId is not null) Interlocked.Exchange(ref _lastKeyedSequence, entry.Sequence);
    }

    public ChainVerificationResult VerifyChain(IReadOnlyList<AuditLogEntry> orderedEntries, long? keyedFrom = null)
    {
        var verifier = BeginVerify(keyedFrom);
        foreach (var entry in orderedEntries)
            if (!verifier.Add(entry)) break;
        return verifier.Result;
    }

    public IChainVerifier BeginVerify(long? keyedFrom = null) => new Verifier(this, keyedFrom);

    // BUG-78: the chain check as a running state, fed one entry at a time.
    private sealed class Verifier(HashChainService svc, long? keyedFrom) : IChainVerifier
    {
        private string _prevHash = GenesisPrevHash;
        private long _expectedSequence = 1;
        private long? _firstKeyed;
        private long? _firstFormat2;   // BUG-184

        public ChainVerificationResult Result { get; private set; } = ChainVerificationResult.Valid;

        public bool Add(AuditLogEntry entry)
        {
            if (!Result.IsValid) return false;
            // BUG-184: once entries are in format 2, an entry in the first format is one rewritten to read differently.
            if (entry.Format is null && _firstFormat2 is { } f2)
            {
                Result = ChainVerificationResult.Broken(entry.Sequence,
                    $"Entry is in the first audit format, but entries have been written in format 2 since #{f2}. It was rewritten.");
                return false;
            }
            if (svc.Check(entry, _expectedSequence, _prevHash, keyedFrom, ref _firstKeyed) is { } broken)
            {
                Result = broken;
                return false;
            }
            if (entry.Format is not null) _firstFormat2 ??= entry.Sequence;
            _prevHash = entry.EntryHash;
            _expectedSequence++;
            return true;
        }
    }

    // One entry against the running state; null when it's sound.
    private ChainVerificationResult? Check(AuditLogEntry entry, long expectedSequence, string prevHash, long? keyedFrom,
        ref long? firstKeyed)
    {
        {
            if (entry.Sequence != expectedSequence)
                return ChainVerificationResult.Broken(entry.Sequence,
                    $"Sequence gap: expected {expectedSequence}, found {entry.Sequence} (entry inserted or removed).");

            if (entry.PrevHash != prevHash)
                return ChainVerificationResult.Broken(entry.Sequence,
                    "Previous-hash link doesn't match the prior entry's hash.");

            // BUG-142: a seal recorded that the chain is keyed from here, which survives a restart.
            if (entry.HashKeyId is null && keyedFrom is { } from && entry.Sequence >= from)
                return ChainVerificationResult.Broken(entry.Sequence,
                    $"Entry has the plain hash, but a signed seal records that the chain is keyed from entry #{from}. It was rewritten without the chain key, or the chain key was turned off.");
            if (entry.HashKeyId is null && entry.Sequence == Interlocked.Read(ref _lastKeyedSequence))
                return ChainVerificationResult.Broken(entry.Sequence,
                    "Entry has the plain hash, but this server wrote it with the chain key. It was rewritten without the chain key.");
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
        }

        return null;
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
