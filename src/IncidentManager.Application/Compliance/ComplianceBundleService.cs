using System.Globalization;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
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

    /// <summary>The bundle in memory (small ranges, tests). A download uses <see cref="WriteAsync"/>.</summary>
    public async Task<ComplianceBundle> BuildAsync(DateTimeOffset fromUtc, DateTimeOffset toUtc,
        CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ComplianceBundleService>(_user);   // the endpoint is Administer-gated too
        using var ms = new MemoryStream();
        var (fileName, model) = await WriteAsync(fromUtc, toUtc, ms, ct);
        return new ComplianceBundle(ms.ToArray(), fileName, model);
    }

    /// <summary>
    /// BUG-256: writes the bundle to <paramref name="output"/>. The chain is verified as a stream (BUG-78), and the range's
    /// entries are read again into the zip as it's written, rather than held in a list beside a zip built in memory (a
    /// year-to-date range on a large log was a gigabyte on the web server's heap).
    /// </summary>
    public async Task<(string FileName, ComplianceBundleModel Model)> WriteAsync(DateTimeOffset fromUtc, DateTimeOffset toUtc,
        Stream output, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ComplianceBundleService>(_user);   // the endpoint is Administer-gated too
        using var db = _factory.CreateDbContext();
        if (toUtc < fromUtc) (fromUtc, toUtc) = (toUtc, fromUtc);

        var allSeals = await db.IntegritySeals.AsNoTracking().OrderBy(s => s.UpToSequence).ToListAsync(ct);

        // The whole chain is verified (each link depends on every one before it), but BUG-78: it's read as a stream and
        // checked one entry at a time. Only the range's entries are kept, plus the hash at each sealed sequence.
        var sealedAt = allSeals.Select(s => s.UpToSequence).ToHashSet();
        var hashBySequence = new Dictionary<long, string>();
        var verifier = _hasher.BeginVerify(await Integrity.IntegrityService.KeyedFromAsync(db, ct));   // BUG-142
        long total = 0, inRange = 0;
        long? firstSeq = null, lastSeq = null;
        (long Sequence, string Hash)? head = null;
        var checking = true;
        await foreach (var e in db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).AsAsyncEnumerable().WithCancellation(ct))
        {
            total++;
            if (checking) checking = verifier.Add(e);
            if (sealedAt.Contains(e.Sequence)) hashBySequence[e.Sequence] = e.EntryHash;
            if (e.AtUtc >= fromUtc && e.AtUtc <= toUtc)   // the segment: entries inside the window
            {
                inRange++;
                firstSeq ??= e.Sequence;
                lastSeq = e.Sequence;
            }
            head = (e.Sequence, e.EntryHash);
        }
        var chainResult = verifier.Result;

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
            Segment: [],
            TotalChainLength: total,
            SegmentFirstSequence: firstSeq,
            SegmentLastSequence: lastSeq,
            ChainResult: chainResult,
            ChainHeadSequence: head?.Sequence,
            ChainHeadHash: head?.Hash,
            Seals: lines,
            CoveringSeal: covering,
            Algorithm: _signer.Algorithm,
            KeyId: _signer.KeyId,
            PublicKeyPem: _signer.PublicKeyPem,
            RetiredKeys: _signer.VerificationKeys.Where(k => !k.Current).ToList(),
            SegmentCount: inRange);

        // The same entries as counted above: in the window, and within the sequence span it found (later ones aren't).
        IEnumerable<AuditLogEntry> segment = firstSeq is { } fs && lastSeq is { } ls
            ? db.AuditLog.AsNoTracking()
                .Where(a => a.Sequence >= fs && a.Sequence <= ls && a.AtUtc >= fromUtc && a.AtUtc <= toUtc)
                .OrderBy(a => a.Sequence).AsEnumerable()
            : [];
        await Task.Run(() => ComplianceBundlePack.Zip(model, output, segment), ct);
        // BUG-531: the name and the audit summary are saved text; Gregorian digits whatever the server culture.
        var inv = CultureInfo.InvariantCulture;
        var fileName = string.Create(inv, $"compliance-bundle-{fromUtc.UtcDateTime:yyyyMMdd}-{toUtc.UtcDateTime:yyyyMMdd}.zip");

        // Recorded after building so the bundle never references its own export line.
        await _audit.RecordAsync(AuditAction.Export, nameof(ComplianceBundle), null, null,
            string.Create(inv, $"Generated compliance evidence bundle covering " +
                $"{fromUtc.UtcDateTime:yyyy-MM-dd}..{toUtc.UtcDateTime:yyyy-MM-dd} ({inRange} entries)"), ct);

        return (fileName, model);
    }

    private SealLine Verify(IntegritySeal seal, IReadOnlyDictionary<long, string> hashBySequence)
    {
        var signatureValid = _signer.Verify(seal.BuildCanonicalContent(), seal.Signature, seal.Algorithm, seal.KeyId);
        var chainMatches = hashBySequence.TryGetValue(seal.UpToSequence, out var h) && h == seal.ChainHeadHash;
        return new SealLine(seal, signatureValid, chainMatches);
    }
}
