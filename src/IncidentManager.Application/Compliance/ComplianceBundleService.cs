using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Compliance;

/// <summary>
/// Builds a compliance evidence bundle (C-01): a single package containing the audit-chain segment for
/// a date range, a whole-chain integrity verification, and the signed seals covering the range — the
/// examiner-ready artifact for a NYDFS §500.17(b) certification file or a DFS examination request. The
/// export itself is recorded in the tamper-evident audit trail.
/// </summary>
public sealed class ComplianceBundleService
{
    private readonly IAppDbContextFactory _factory;
    private readonly IHashChainService _hasher;
    private readonly ISealSigner _signer;
    private readonly IUserDirectory _users;
    private readonly IAuditWriter _audit;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public ComplianceBundleService(IAppDbContextFactory factory, IHashChainService hasher, ISealSigner signer,
        IUserDirectory users, IAuditWriter audit, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _hasher = hasher;
        _signer = signer;
        _users = users;
        _audit = audit;
        _user = user;
        _clock = clock;
    }

    public async Task<ComplianceBundle> BuildAsync(DateTimeOffset fromUtc, DateTimeOffset toUtc,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        if (toUtc < fromUtc) (fromUtc, toUtc) = (toUtc, fromUtc);

        // The whole chain (ordered) — verification depends on every prior link, and it lets us resolve
        // each seal's head hash without extra queries.
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync(ct);
        var chainResult = _hasher.VerifyChain(chain);
        var head = chain.Count > 0 ? chain[^1] : null;
        var hashBySequence = chain.ToDictionary(a => a.Sequence, a => a.EntryHash);

        // The segment: entries whose timestamp falls within the requested window.
        var segment = chain.Where(a => a.AtUtc >= fromUtc && a.AtUtc <= toUtc).ToList();
        long? firstSeq = segment.Count > 0 ? segment[0].Sequence : null;
        long? lastSeq = segment.Count > 0 ? segment[^1].Sequence : null;

        var allSeals = await db.IntegritySeals.AsNoTracking().OrderBy(s => s.UpToSequence).ToListAsync(ct);

        // The covering seal: the earliest seal whose coverage reaches the segment's last entry, so the
        // bundle can attest that the whole range is under seal even if the seal was written later.
        SealLine? covering = null;
        if (lastSeq is { } last)
        {
            var cover = allSeals.FirstOrDefault(s => s.UpToSequence >= last);
            if (cover is not null) covering = Verify(cover, hashBySequence);
        }

        // Plus any seals that were themselves recorded during the window.
        var lines = allSeals
            .Where(s => s.SealedAtUtc >= fromUtc && s.SealedAtUtc <= toUtc)
            .Select(s => Verify(s, hashBySequence))
            .ToList();
        if (covering is not null && lines.All(l => l.Seal.Id != covering.Seal.Id))
            lines.Add(covering);
        lines = lines.OrderBy(l => l.Seal.UpToSequence).ToList();

        var model = new ComplianceBundleModel(
            GeneratedAtUtc: _clock.UtcNow,
            GeneratedByDisplay: _users.DisplayFor(_user.UserId),
            GeneratedByUserId: _user.UserId,
            FromUtc: fromUtc,
            ToUtc: toUtc,
            Segment: segment,
            TotalChainLength: chain.Count,
            SegmentFirstSequence: firstSeq,
            SegmentLastSequence: lastSeq,
            ChainResult: chainResult,
            ChainHeadSequence: head?.Sequence,
            ChainHeadHash: head?.EntryHash,
            Seals: lines,
            CoveringSeal: covering,
            Algorithm: _signer.Algorithm,
            KeyId: _signer.KeyId,
            PublicKeyPem: _signer.PublicKeyPem);

        var bytes = ComplianceBundlePack.Zip(model);
        var fileName = $"compliance-bundle-{fromUtc.UtcDateTime:yyyyMMdd}-{toUtc.UtcDateTime:yyyyMMdd}.zip";

        // Recorded after building so the bundle never references its own export line.
        await _audit.RecordAsync(AuditAction.Export, nameof(ComplianceBundle), null, null,
            $"Generated compliance evidence bundle covering " +
            $"{fromUtc.UtcDateTime:yyyy-MM-dd}..{toUtc.UtcDateTime:yyyy-MM-dd} ({segment.Count} entries)", ct);

        return new ComplianceBundle(bytes, fileName, model);
    }

    private SealLine Verify(IntegritySeal seal, IReadOnlyDictionary<long, string> hashBySequence)
    {
        var signatureValid = _signer.Verify(seal.BuildCanonicalContent(), seal.Signature);
        var chainMatches = hashBySequence.TryGetValue(seal.UpToSequence, out var h) && h == seal.ChainHeadHash;
        return new SealLine(seal, signatureValid, chainMatches);
    }
}
