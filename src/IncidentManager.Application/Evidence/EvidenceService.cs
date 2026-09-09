using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Evidence;

/// <summary>
/// Attaches and retrieves evidence. Uploads are hashed and recorded immutably with a chain-of-
/// custody entry; downloads append a custody entry too. Files are streamed, never executed.
/// </summary>
public sealed class EvidenceService
{
    private readonly IAppDbContextFactory _factory;
    private readonly IEvidenceStore _store;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public EvidenceService(IAppDbContextFactory factory, IEvidenceStore store, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _store = store;
        _user = user;
        _clock = clock;
    }

    public async Task<Domain.Entities.Evidence> UploadAsync(Guid caseId, string fileName, string contentType,
        Stream content, string? description, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
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

    public async Task<List<ChainOfCustodyEvent>> GetCustodyAsync(Guid evidenceId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await db.CustodyEvents.AsNoTracking()
            .Where(e => e.EvidenceId == evidenceId)
            .OrderBy(e => e.AtUtc)
            .ToListAsync(ct);
    }
}
