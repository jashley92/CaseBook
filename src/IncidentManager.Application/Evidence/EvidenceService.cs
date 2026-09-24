using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Evidence;

/// <summary>
/// Attaches and retrieves evidence. Uploads are hashed and recorded immutably with a chain-of-
/// custody entry; downloads, in-app views and recorded hand-offs append custody entries too (PROD-13).
/// Files are streamed, never executed.
/// </summary>
public sealed class EvidenceService
{
    private readonly IAppDbContextFactory _factory;
    private readonly IEvidenceStore _store;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly IAuditWriter _audit;

    public EvidenceService(IAppDbContextFactory factory, IEvidenceStore store, ICurrentUser user, IClock clock,
        IAuditWriter audit)
    {
        _factory = factory;
        _store = store;
        _user = user;
        _clock = clock;
        _audit = audit;
    }

    public async Task<Domain.Entities.Evidence> UploadAsync(Guid caseId, string fileName, string contentType,
        Stream content, string? description, CancellationToken ct = default)
    {
        // S-09: uploading is a case edit, and only onto a case the caller can see (checked before any bytes are stored).
        if (!_user.Has(Permission.EditCases)) throw new ForbiddenException(Permission.EditCases, nameof(UploadAsync));
        using var db = _factory.CreateDbContext();
        if (!await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct))
            throw new InvalidOperationException("Case not found or not accessible.");
        var stored = await _store.SaveAsync(caseId, content, ct);

        var evidence = new Domain.Entities.Evidence
        {
            CaseId = caseId,
            OriginalFileName = fileName,
            ContentType = string.IsNullOrWhiteSpace(contentType) ? "application/octet-stream" : contentType,
            SizeBytes = stored.SizeBytes,
            Sha256 = stored.Sha256,
            StoragePath = stored.StoragePath,
            Description = description,
            CreatedBy = _user.UserId,
            CreatedAtUtc = _clock.UtcNow
        };
        evidence.CustodyEvents.Add(new ChainOfCustodyEvent
        {
            EvidenceId = evidence.Id, AtUtc = _clock.UtcNow, Actor = _user.UserId,
            Action = "Uploaded", Details = $"{stored.SizeBytes} bytes; sha256={stored.Sha256}"
        });

        db.Evidence.Add(evidence);
        await db.SaveChangesAsync(ct);
        return evidence;
    }

    /// <summary>
    /// Opens evidence for reading. Need-to-know on the parent case is enforced either way (a restricted
    /// case's evidence is never reachable by GUID alone; same "not found" message so existence doesn't
    /// leak). When <paramref name="recordDownload"/> is true — an explicit human download — a "Downloaded"
    /// chain-of-custody event is appended. Passive/automated reads (the Timeline inline thumbnail) pass
    /// false so the custody record reflects only real downloads, not UI renders: opening the Timeline tab
    /// must not fabricate "Downloaded" events an examiner would read as human access (S-03).
    /// </summary>
    public async Task<(Domain.Entities.Evidence Evidence, Stream Content)> OpenAsync(
        Guid evidenceId, bool recordDownload = true, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var evidence = await db.Evidence.FirstOrDefaultAsync(e => e.Id == evidenceId, ct)
                       ?? throw new InvalidOperationException("Evidence not found.");

        var canAccess = await db.Cases.AsNoTracking().ForUser(_user)
            .AnyAsync(c => c.Id == evidence.CaseId, ct);
        if (!canAccess) throw new InvalidOperationException("Evidence not found.");

        if (recordDownload)
        {
            evidence.CustodyEvents.Add(new ChainOfCustodyEvent
            {
                EvidenceId = evidence.Id, AtUtc = _clock.UtcNow, Actor = _user.UserId, Action = "Downloaded"
            });
            await db.SaveChangesAsync(ct);
        }

        var stream = await _store.OpenReadAsync(evidence.StoragePath, ct);
        return (evidence, stream);
    }

    /// <summary>
    /// Repeat views by the same person inside this window collapse into the first one, so flicking a preview
    /// open and closed doesn't bury the custody record in noise. A view by someone else always records.
    /// </summary>
    public static readonly TimeSpan ViewDedupWindow = TimeSpan.FromMinutes(10);

    /// <summary>
    /// PROD-13: records a "Viewed" custody event when a person deliberately opens evidence in the app (the
    /// preview lightbox). Deliberately <em>not</em> tied to the <c>/inline</c> image fetch — thumbnails load
    /// passively whenever a tab renders, and an examiner must be able to read every entry as a human act
    /// (the same reasoning as S-03). Need-to-know on the parent case applies. Returns false when the view was
    /// folded into a recent one (<see cref="ViewDedupWindow"/>).
    /// </summary>
    public async Task<bool> RecordViewedAsync(Guid evidenceId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var evidence = await LoadScopedAsync(db, evidenceId, ct);

        var since = _clock.UtcNow - ViewDedupWindow;
        var recent = await db.CustodyEvents.AsNoTracking()
            .Where(e => e.EvidenceId == evidenceId && e.Actor == _user.UserId && e.Action == "Viewed")
            .Select(e => e.AtUtc)
            .ToListAsync(ct);   // DateTimeOffset comparison stays client-side for SQLite
        if (recent.Any(t => t >= since)) return false;

        evidence.CustodyEvents.Add(new ChainOfCustodyEvent
        {
            EvidenceId = evidence.Id, AtUtc = _clock.UtcNow, Actor = _user.UserId, Action = "Viewed",
            Details = "Previewed in CaseBook"
        });
        await db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>
    /// PROD-13: records a hand-off of a copy of the evidence outside CaseBook (outside counsel, law
    /// enforcement, a forensics firm, a regulator). No export ships evidence bytes, so a transfer is always a
    /// real-world act the analyst attests to here: who received it, how, and why. Requires
    /// <see cref="Permission.EditCases"/> and need-to-know on the case. Custody rows sit outside the audit chain
    /// by design (downloads/views are access telemetry), but a transfer is an attested decision, so it is also
    /// written to the hash-chained audit log explicitly.
    /// </summary>
    public async Task<ChainOfCustodyEvent> RecordTransferAsync(Guid evidenceId, string recipient, string? method,
        string purpose, CancellationToken ct = default)
    {
        if (!_user.Has(Permission.EditCases)) throw new ForbiddenException(Permission.EditCases, nameof(RecordTransferAsync));
        recipient = (recipient ?? "").Trim();
        purpose = (purpose ?? "").Trim();
        method = string.IsNullOrWhiteSpace(method) ? null : method.Trim();
        if (recipient.Length == 0) throw new ArgumentException("Say who received the evidence.");
        if (purpose.Length == 0) throw new ArgumentException("Give the purpose of the transfer.");
        if (recipient.Length > 200 || purpose.Length > 500 || method?.Length > 100)
            throw new ArgumentException("Keep the recipient to 200 characters, the method to 100 and the purpose to 500.");

        using var db = _factory.CreateDbContext();
        var evidence = await LoadScopedAsync(db, evidenceId, ct);

        var custody = new ChainOfCustodyEvent
        {
            EvidenceId = evidence.Id, AtUtc = _clock.UtcNow, Actor = _user.UserId, Action = "Transferred",
            Details = method is null ? $"To {recipient}. Purpose: {purpose}" : $"To {recipient} via {method}. Purpose: {purpose}"
        };
        evidence.CustodyEvents.Add(custody);
        await db.SaveChangesAsync(ct);

        var caseNumber = await db.Cases.AsNoTracking().Where(c => c.Id == evidence.CaseId)
            .Select(c => c.CaseNumber).FirstOrDefaultAsync(ct);
        await _audit.RecordAsync(AuditAction.EvidenceTransferred, nameof(Domain.Entities.Evidence), evidence.Id.ToString(),
            caseNumber, $"Transferred {evidence.OriginalFileName} (sha256 {evidence.Sha256[..12]}…). {custody.Details}", ct);
        return custody;
    }

    /// <summary>Loads evidence for a write, enforcing need-to-know on the parent case ("not found" either way).</summary>
    private async Task<Domain.Entities.Evidence> LoadScopedAsync(IAppDbContext db, Guid evidenceId, CancellationToken ct)
    {
        var evidence = await db.Evidence.FirstOrDefaultAsync(e => e.Id == evidenceId, ct)
                       ?? throw new InvalidOperationException("Evidence not found.");
        var canAccess = await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == evidence.CaseId, ct);
        if (!canAccess) throw new InvalidOperationException("Evidence not found.");
        return evidence;
    }

    public async Task<List<ChainOfCustodyEvent>> GetCustodyAsync(Guid evidenceId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        // Same need-to-know scope as the file itself: a restricted case's custody trail isn't readable by GUID.
        var caseId = await db.Evidence.AsNoTracking().Where(e => e.Id == evidenceId).Select(e => (Guid?)e.CaseId)
            .FirstOrDefaultAsync(ct);
        if (caseId is null || !await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct))
            return new List<ChainOfCustodyEvent>();
        return await db.CustodyEvents.AsNoTracking()
            .Where(e => e.EvidenceId == evidenceId)
            .OrderBy(e => e.AtUtc)
            .ToListAsync(ct);
    }
}
