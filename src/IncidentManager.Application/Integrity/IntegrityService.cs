using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Integrity;

/// <summary>
/// Verifies and seals the audit chain. Verification recomputes the whole chain and reports the
/// first break; sealing records a signed chain-head snapshot for independent later comparison.
/// </summary>
public sealed class IntegrityService
{
    private readonly IAppDbContextFactory _factory;
    private readonly IHashChainService _hasher;
    private readonly ISealSigner _signer;
    private readonly ISealStore _sealStore;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly IIntegrityMonitor _monitor;
    private readonly IIntegrityAlertNotifier _alerts;

    public IntegrityService(IAppDbContextFactory factory, IHashChainService hasher, ISealSigner signer,
        ISealStore sealStore, ICurrentUser user, IClock clock, IIntegrityMonitor monitor,
        IIntegrityAlertNotifier alerts)
    {
        _factory = factory;
        _hasher = hasher;
        _signer = signer;
        _sealStore = sealStore;
        _user = user;
        _clock = clock;
        _monitor = monitor;
        _alerts = alerts;
    }

    public async Task<ChainVerificationResult> VerifyAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync(ct);
        return _hasher.VerifyChain(chain);
    }

    /// <summary>
    /// Verifies the chain, records the outcome for the app-wide integrity banner, and — on the first
    /// detection of a break — fires the alarm (SIEM/critical log + email). Used by the background monitor
    /// and by the manual "Verify now" action, so any detection path raises the same alert exactly once
    /// per broken episode. The notifier never throws, so a notification failure can't hide the break.
    /// </summary>
    public async Task<ChainVerificationResult> VerifyAndTrackAsync(CancellationToken ct = default)
    {
        var result = await VerifyAsync(ct);

        // VerifyAsync is the unkeyed self-consistency check — a tamperer who recomputes every hash would
        // pass it. The signed seals are the independent anchor, but they were only ever checked on demand
        // (a manual "verify seal" / a compliance export). Verify the most-covering seal here too, so a
        // competent rewrite of sealed history (or an altered/re-signed seal) trips the same F-16 alarm
        // automatically on the monitor's cadence, not only when someone happens to run a manual check (S-05).
        if (result.IsValid && await VerifyLatestSealAsync(ct) is { } sc && !sc.Result.IsValid)
            result = ChainVerificationResult.Broken(sc.Sequence, "Seal check failed — " + sc.Result.Detail);

        if (_monitor.RecordResult(result, _clock.UtcNow))
            await _alerts.OnChainBrokenAsync(result, ct);
        return result;
    }

    /// <summary>
    /// Verifies the seal covering the most history (highest <see cref="IntegritySeal.UpToSequence"/>)
    /// against the live chain — signature authentic AND the sealed head hash still matches the audit entry
    /// at that sequence. Because the chain is linear, a match proves all history up to that sequence is
    /// unchanged since sealing. Returns null when no seal exists yet.
    /// </summary>
    public async Task<(long Sequence, SealVerificationResult Result)?> VerifyLatestSealAsync(CancellationToken ct = default)
    {
        Guid sealId;
        long upTo;
        using (var db = _factory.CreateDbContext())
        {
            var latest = await db.IntegritySeals.AsNoTracking()
                .OrderByDescending(s => s.UpToSequence).FirstOrDefaultAsync(ct);
            if (latest is null) return null;
            sealId = latest.Id;
            upTo = latest.UpToSequence;
        }
        return (upTo, await VerifySealAsync(sealId, ct));
    }

    /// <summary>The timestamp of the most recent seal, or null if none exists — for cadence decisions.</summary>
    public async Task<DateTimeOffset?> LatestSealAtUtc(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var latest = await db.IntegritySeals.AsNoTracking()
            .OrderByDescending(s => s.SealedAtUtc).FirstOrDefaultAsync(ct);
        return latest?.SealedAtUtc;
    }

    /// <summary>
    /// Records a seal only when at least <paramref name="minInterval"/> has elapsed since the most recent
    /// one (or none exists yet), so the monitor can verify frequently while seals stay on a slower cadence.
    /// Returns the new seal, or null if none was due (or the chain is empty).
    /// </summary>
    public async Task<IntegritySeal?> SealIfDueAsync(TimeSpan minInterval, CancellationToken ct = default)
    {
        if (await LatestSealAtUtc(ct) is { } last && _clock.UtcNow - last < minInterval)
            return null;
        return await SealAsync(ct);
    }

    public async Task<int> AuditCountAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await db.AuditLog.CountAsync(ct);
    }

    public async Task<List<AuditLogEntry>> RecentAsync(string? caseNumber, int take = 100, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var q = db.AuditLog.AsNoTracking().AsQueryable();
        if (!string.IsNullOrWhiteSpace(caseNumber))
            q = q.Where(a => a.CaseNumber == caseNumber);
        return await q.OrderByDescending(a => a.Sequence).Take(take).ToListAsync(ct);
    }

    /// <summary>
    /// Filtered read over the hash-chained audit trail (E-24). Fields on <paramref name="filter"/>
    /// AND together; blank fields are ignored. Server-side filtering (rather than trimming a client-side
    /// top-N) so an actor/date-range question answers over the whole history. Newest first.
    /// </summary>
    public async Task<List<AuditLogEntry>> QueryAsync(AuditQueryFilter filter, int take = 500, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var q = db.AuditLog.AsNoTracking().AsQueryable();

        if (!string.IsNullOrWhiteSpace(filter.CaseNumber))
            q = q.Where(a => a.CaseNumber == filter.CaseNumber);
        if (!string.IsNullOrWhiteSpace(filter.Actor))
            q = q.Where(a => a.Actor == filter.Actor);
        if (filter.Action is { } action)
            q = q.Where(a => a.Action == action);
        if (!string.IsNullOrWhiteSpace(filter.EntityType))
            q = q.Where(a => a.EntityType == filter.EntityType);
        if (filter.FromUtc is { } from)
            q = q.Where(a => a.AtUtc >= from);
        if (filter.ToUtc is { } to)
            q = q.Where(a => a.AtUtc <= to);

        return await q.OrderByDescending(a => a.Sequence).Take(take).ToListAsync(ct);
    }

    /// <summary>
    /// Distinct actors and entity types present in the audit trail (optionally scoped to one case),
    /// to populate the E-24 filter dropdowns so the choices always reflect the real history.
    /// </summary>
    public async Task<(List<string> Actors, List<string> EntityTypes)> AuditFacetsAsync(string? caseNumber, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var q = db.AuditLog.AsNoTracking().AsQueryable();
        if (!string.IsNullOrWhiteSpace(caseNumber))
            q = q.Where(a => a.CaseNumber == caseNumber);
        var actors = await q.Select(a => a.Actor).Distinct().OrderBy(x => x).ToListAsync(ct);
        var types = await q.Select(a => a.EntityType).Distinct().OrderBy(x => x).ToListAsync(ct);
        return (actors, types);
    }

    /// <summary>
    /// Records a signed seal over the current chain head and exports a copy out of band. The seal is
    /// signed with an asymmetric key (<see cref="ISealSigner"/>) so its authenticity can be verified
    /// independently of the database later.
    /// </summary>
    public async Task<IntegritySeal?> SealAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var head = await db.AuditLog.AsNoTracking().OrderByDescending(a => a.Sequence).FirstOrDefaultAsync(ct);
        if (head is null) return null;

        var seal = new IntegritySeal
        {
            SealedAtUtc = _clock.UtcNow,
            UpToSequence = head.Sequence,
            ChainHeadHash = head.EntryHash,
            SealedBy = _user.UserId,
            Algorithm = _signer.Algorithm,
            KeyId = _signer.KeyId
        };
        seal.Signature = _signer.Sign(seal.BuildCanonicalContent());

        db.IntegritySeals.Add(seal);
        await db.SaveChangesAsync(ct);

        // Best-effort out-of-band export; a failure here must not roll back a persisted seal.
        try { await _sealStore.ExportAsync(seal, ct); } catch { /* logged upstream; DB copy stands */ }

        return seal;
    }

    /// <summary>
    /// Verifies a stored seal: its signature must be authentic (proving the sealed values are
    /// unaltered and signed by our key), and its recorded chain-head hash must still match the live
    /// audit entry at that sequence (proving history has not been rewritten since it was sealed).
    /// </summary>
    public async Task<SealVerificationResult> VerifySealAsync(Guid sealId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var seal = await db.IntegritySeals.AsNoTracking().FirstOrDefaultAsync(s => s.Id == sealId, ct);
        if (seal is null) return new SealVerificationResult(false, false, "Seal not found.");

        var signatureValid = _signer.Verify(seal.BuildCanonicalContent(), seal.Signature);

        var entry = await db.AuditLog.AsNoTracking()
            .FirstOrDefaultAsync(a => a.Sequence == seal.UpToSequence, ct);
        var chainMatches = entry is not null && entry.EntryHash == seal.ChainHeadHash;

        var detail = (signatureValid, chainMatches) switch
        {
            (true, true) => "Signature authentic and the chain head is unchanged since sealing.",
            (false, _) => "Signature invalid — the seal record was altered or signed by a different key.",
            (true, false) when entry is null => $"No audit entry at sealed sequence {seal.UpToSequence} — history was truncated.",
            (true, false) => $"Chain head at sequence {seal.UpToSequence} differs from the seal — history was rewritten after sealing.",
        };
        return new SealVerificationResult(signatureValid, chainMatches, detail);
    }

    public async Task<List<IntegritySeal>> RecentSealsAsync(int take = 20, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await db.IntegritySeals.AsNoTracking().OrderByDescending(s => s.SealedAtUtc).Take(take).ToListAsync(ct);
    }
}

/// <summary>Outcome of verifying a single integrity seal.</summary>
public sealed record SealVerificationResult(bool SignatureValid, bool ChainMatches, string Detail)
{
    public bool IsValid => SignatureValid && ChainMatches;
}
