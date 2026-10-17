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
    private readonly Microsoft.Extensions.Options.IOptionsMonitor<EvidenceStorageOptions>? _limits;   // PROD-55
    private readonly EvidenceUploadSessions? _uploads;   // PROD-56

    public EvidenceService(IAppDbContextFactory factory, IEvidenceStore store, ICurrentUser user, IClock clock,
        IAuditWriter audit, Microsoft.Extensions.Options.IOptionsMonitor<EvidenceStorageOptions>? limits = null,
        EvidenceUploadSessions? uploads = null)
    {
        _limits = limits;
        _uploads = uploads;
        _factory = factory;
        _store = store;
        _user = user;
        _clock = clock;
        _audit = audit;
    }

    /// <summary>The administrator's storage limits in force (PROD-55).</summary>
    public EvidenceStorageOptions Limits => _limits?.CurrentValue ?? new();

    /// <summary>PROD-55: what evidence takes against its limits (Diagnostics, and the uploader's 90 % warning).</summary>
    public async Task<EvidenceStorageUse> StorageUseAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await EvidenceRoom.UseAsync(db, _store, Limits, withVolume: true, ct: ct);
    }

    /// <summary>
    /// PROD-55: <paramref name="size"/> is the size the browser declared, checked against the limits before any byte is
    /// stored; the bytes actually read are held to the largest file allowed, and checked again once stored.
    /// </summary>
    public async Task<Domain.Entities.Evidence> UploadAsync(Guid caseId, string fileName, string contentType,
        Stream content, string? description, long? size = null, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        await CheckCanUploadAsync(db, caseId, fileName, description, ct);
        var limits = Limits;
        await EvidenceRoom.CheckAsync(db, _store, limits, size ?? 0, ct);
        await using var held = new LimitedReadStream(content, limits.MaxUploadBytes,
            () => new ArgumentException($"That file is larger than {EvidenceRoom.Size(limits.MaxUploadBytes)}, the largest file CaseBook takes."));
        var stored = await _store.SaveAsync(caseId, held, ct);
        if (stored.SizeBytes != size)
        {
            // The size wasn't declared, or the bytes differ from it: the stored size decides.
            try { await EvidenceRoom.CheckAsync(db, _store, limits, stored.SizeBytes, ct); }
            catch
            {
                await _store.DiscardUnrecordedAsync(stored.StoragePath);
                throw;
            }
        }
        return await RecordAsync(db, caseId, fileName, contentType, description, stored, ct);
    }

    // S-09: uploading is a case edit, and only onto a case the caller can see (checked before any bytes are stored, and
    // again when a large upload completes). BUG-206: what the record can't hold is refused before any bytes are stored.
    private async Task CheckCanUploadAsync(IAppDbContext db, Guid caseId, string fileName, string? description, CancellationToken ct)
    {
        if (!_user.Has(Permission.EditCases)) throw new ForbiddenException(Permission.EditCases, nameof(UploadAsync));
        if (!await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct))
            throw new InvalidOperationException("Case not found or not accessible.");
        if (description is { Length: > MaxDescriptionLength })
            throw new ArgumentException($"Keep the description to {MaxDescriptionLength:N0} characters or fewer.");
        if (fileName is { Length: > MaxFileNameLength })
            throw new ArgumentException($"That file name is longer than {MaxFileNameLength} characters. Rename the file and upload it again.");
    }

    // The record, its "Uploaded" custody event and (through the save) its audit entry, for a file already in the store;
    // the same for both upload paths. BUG-206: a file whose record can't be saved is removed, so no bytes sit unrecorded.
    private async Task<Domain.Entities.Evidence> RecordAsync(IAppDbContext db, Guid caseId, string fileName, string contentType,
        string? description, StoredEvidence stored, CancellationToken ct)
    {
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
        try { await db.SaveChangesAsync(ct); }
        catch
        {
            await _store.DiscardUnrecordedAsync(stored.StoragePath);   // BUG-206: no bytes without a record
            throw;
        }
        return evidence;
    }

    /// <summary>BUG-206: the record's limits (its columns), checked before a file is stored.</summary>
    public const int MaxDescriptionLength = 2000, MaxFileNameLength = 500;

    /// <summary>PROD-56: a large upload started: its id, the size of each part, and how many parts to send.</summary>
    public sealed record UploadStarted(string Id, int PartBytes, int Parts);

    private EvidenceUploadSessions Uploads =>
        _uploads ?? throw new InvalidOperationException("Large uploads aren't available on this server.");

    private EvidenceUploadSessions.Session Owned(string id) =>
        Uploads.Find(id, _user.UserId) ?? throw new Common.NotFoundException("That upload isn't in progress. Start it again.");

    /// <summary>
    /// PROD-56: starts a large upload, sent in parts. The same checks as an in-page upload (permission, the case, the
    /// record's limits, the size and room) are made before anything is written.
    /// </summary>
    public async Task<UploadStarted> BeginUploadAsync(Guid caseId, string fileName, string contentType, long size,
        string? description, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        await CheckCanUploadAsync(db, caseId, fileName, description, ct);
        if (size <= 0) throw new ArgumentException("That file is empty.");
        await EvidenceRoom.CheckAsync(db, _store, Limits, size, ct);
        var incoming = await _store.BeginIncomingAsync(ct);
        try
        {
            var s = Uploads.Create(_user.UserId, caseId, fileName,
                string.IsNullOrWhiteSpace(contentType) ? "application/octet-stream" : contentType, description, size, incoming,
                _clock.UtcNow);
            return new UploadStarted(s.Id, EvidenceUploadSessions.PartBytes, s.Parts);
        }
        catch
        {
            await _store.DiscardIncomingAsync(incoming);
            throw;
        }
    }

    /// <summary>
    /// PROD-56: writes part <paramref name="part"/> (from 0) of an upload and returns the bytes received so far. A part
    /// already written is acknowledged and ignored (a retry whose answer was lost); one out of order is refused. Every part
    /// re-checks the person may still edit the case.
    /// </summary>
    public async Task<long> AppendPartAsync(string id, int part, ReadOnlyMemory<byte> bytes, CancellationToken ct = default)
    {
        var s = Owned(id);
        await s.Gate.WaitAsync(ct);
        try
        {
            if (s.Ended) throw new InvalidOperationException("That upload has already finished.");
            await StillAllowedAsync(s.CaseId, ct);
            if (part < s.NextPart) return s.Committed;
            if (part > s.NextPart || part >= s.Parts)
                throw new InvalidOperationException($"Part {part + 1} arrived before part {s.NextPart + 1}. Start the upload again.");
            var expected = part == s.Parts - 1 ? s.Size - s.Committed : EvidenceUploadSessions.PartBytes;
            if (bytes.Length != expected)
                throw new ArgumentException($"Part {part + 1} should be {expected:N0} bytes, but {bytes.Length:N0} arrived.");
            await _store.AppendIncomingAsync(s.Incoming, s.Committed, bytes, ct);
            s.Hash.AppendData(bytes.Span);
            s.Committed += bytes.Length;
            s.NextPart++;
            s.LastActivity = _clock.UtcNow;
            return s.Committed;
        }
        finally { s.Gate.Release(); }
    }

    /// <summary>
    /// PROD-56: finishes an upload once every part is in: the checks again (the permission may have been withdrawn, the
    /// limits changed), the read-back check when it's on, then the file moves into place and is recorded as an in-page
    /// upload is. Finishing twice answers with the same record.
    /// </summary>
    public async Task<Domain.Entities.Evidence> CompleteUploadAsync(string id, CancellationToken ct = default)
    {
        var s = Owned(id);
        await s.Gate.WaitAsync(ct);
        try
        {
            using var db = _factory.CreateDbContext();
            if (s.EvidenceId is { } done)
                return await db.Evidence.AsNoTracking().FirstAsync(e => e.Id == done, ct);
            if (s.Ended) throw new InvalidOperationException("That upload was cancelled. Start it again.");
            if (s.Committed != s.Size)
                throw new InvalidOperationException($"The upload is missing parts: {s.Committed:N0} of {s.Size:N0} bytes arrived.");
            await CheckCanUploadAsync(db, s.CaseId, s.FileName, s.Description, ct);
            await EvidenceRoom.CheckAsync(db, _store, Limits, s.Size, ct);
            var sha = Convert.ToHexString(s.Hash.GetCurrentHash()).ToLowerInvariant();
            await _store.FinishIncomingAsync(s.Incoming, s.Size, ct);   // PROD-57: an encrypted file's final chunk
            if (Limits.ReadBackCheck && !await ReadsBackAsync(s, sha, ct))
            {
                await EndAsync(s);
                throw new ArgumentException("The file was damaged on its way to the evidence store, so it wasn't kept. Upload it again.");
            }
            var stored = await _store.CommitIncomingAsync(s.Incoming, s.CaseId, sha, s.Size, ct);
            s.Ended = true;   // the parts are now the stored file: abandoning must not touch them
            var evidence = await RecordAsync(db, s.CaseId, s.FileName, s.ContentType, s.Description, stored, ct);
            s.EvidenceId = evidence.Id;
            s.LastActivity = _clock.UtcNow;
            return evidence;
        }
        finally { s.Gate.Release(); }
    }

    // PROD-56: the parts as stored hash to what arrived, so a write damaged on its way to a share isn't recorded.
    private async Task<bool> ReadsBackAsync(EvidenceUploadSessions.Session s, string sha, CancellationToken ct)
    {
        await using var read = await _store.OpenIncomingAsync(s.Incoming, ct);
        var again = Convert.ToHexString(await System.Security.Cryptography.SHA256.HashDataAsync(read, ct)).ToLowerInvariant();
        return string.Equals(again, sha, StringComparison.Ordinal);
    }

    /// <summary>PROD-56: cancels an upload in progress and deletes its parts. Cancelling a finished upload does nothing.</summary>
    public async Task AbandonUploadAsync(string id, CancellationToken ct = default)
    {
        var s = Owned(id);
        await s.Gate.WaitAsync(ct);
        try
        {
            if (!s.Ended) await EndAsync(s);
        }
        finally { s.Gate.Release(); }
    }

    private async Task EndAsync(EvidenceUploadSessions.Session s)
    {
        s.Ended = true;
        s.LastActivity = _clock.UtcNow;
        await _store.DiscardIncomingAsync(s.Incoming);
    }

    /// <summary>
    /// PROD-56: drops uploads idle past <see cref="EvidenceUploadSessions.IdleLimit"/> (deleting their parts) and finished
    /// ones past <see cref="EvidenceUploadSessions.DoneKept"/>, then any parts older than <paramref name="orphansOlderThan"/>
    /// left by an upload no longer held (a restart). Returns how many it removed.
    /// </summary>
    public static async Task<int> SweepUploadsAsync(EvidenceUploadSessions uploads, IEvidenceStore store, DateTimeOffset now,
        TimeSpan orphansOlderThan, CancellationToken ct = default)
    {
        var dropped = 0;
        foreach (var s in uploads.Stale(now))
        {
            await s.Gate.WaitAsync(ct);
            try
            {
                if (!s.Ended) await store.DiscardIncomingAsync(s.Incoming);
                s.Ended = true;
                uploads.Forget(s);
                dropped++;
            }
            finally { s.Gate.Release(); }
        }
        return dropped + await store.ClearIncomingAsync(orphansOlderThan, ct);
    }

    private async Task StillAllowedAsync(Guid caseId, CancellationToken ct)
    {
        if (!_user.Has(Permission.EditCases)) throw new ForbiddenException(Permission.EditCases, nameof(AppendPartAsync));
        using var db = _factory.CreateDbContext();
        if (!await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct))
            throw new InvalidOperationException("Case not found or not accessible.");
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
        Guid evidenceId, bool recordDownload = true, string? downloadDetails = null, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var evidence = await db.Evidence.FirstOrDefaultAsync(e => e.Id == evidenceId, ct)
                       ?? throw new Common.NotFoundException("Evidence not found.");

        var canAccess = await db.Cases.AsNoTracking().ForUser(_user)
            .AnyAsync(c => c.Id == evidence.CaseId, ct);
        if (!canAccess) throw new Common.NotFoundException("Evidence not found.");

        // BUG-197: the file is opened first, so a download that can't be served (the file missing or unreadable) records
        // no custody event for bytes that never left the server.
        var stream = await _store.OpenReadAsync(evidence.StoragePath, ct);
        if (recordDownload)
        {
            try
            {
                evidence.CustodyEvents.Add(new ChainOfCustodyEvent
                {
                    EvidenceId = evidence.Id, AtUtc = _clock.UtcNow, Actor = _user.UserId, Action = "Downloaded",
                    Details = downloadDetails   // PROD-58: how, e.g. in a password-protected zip
                });
                await db.SaveChangesAsync(ct);
            }
            catch
            {
                await stream.DisposeAsync();
                throw;
            }
        }
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
        // BUG-598: a damaged row's short hash threw here, after the custody row was saved (no audit line; a retry doubled it).
        await _audit.RecordAsync(AuditAction.EvidenceTransferred, nameof(Domain.Entities.Evidence), evidence.Id.ToString(),
            caseNumber, $"Transferred {evidence.OriginalFileName} (sha256 {Common.ShortHash.Of(evidence.Sha256)}). {custody.Details}", ct);
        return custody;
    }

    /// <summary>RD-06: file types whose start can be shown as text in the evidence drawer.</summary>
    public static bool IsTextPreviewable(string? contentType, string? fileName)
    {
        var ct = (contentType ?? "").ToLowerInvariant();
        if (ct.StartsWith("text/", StringComparison.Ordinal) || ct is "application/json" or "application/xml" or "application/x-ndjson" or "message/rfc822")
            return true;
        var ext = Path.GetExtension(fileName ?? "").ToLowerInvariant();
        return ext is ".txt" or ".csv" or ".tsv" or ".log" or ".json" or ".ndjson" or ".xml" or ".eml" or ".md" or ".yaml" or ".yml"
            or ".ini" or ".conf" or ".cfg" or ".evtx.txt" or ".ps1" or ".sh" or ".py" or ".js" or ".html" or ".htm";
    }

    /// <summary>
    /// RD-06: the first lines of a text file (up to <paramref name="maxBytes"/>), for the evidence drawer's preview.
    /// Opening a preview is a deliberate look, so it records a "Viewed" custody event the same way the image preview
    /// does (folded into a recent view by the same person). Need-to-know applies. Null for files that aren't text,
    /// including any whose first bytes contain a NUL (binary under a text name).
    /// </summary>
    public async Task<string?> PreviewTextAsync(Guid evidenceId, int maxBytes = 4096, CancellationToken ct = default)
    {
        var (evidence, stream) = await OpenAsync(evidenceId, recordDownload: false, ct: ct);
        await using (stream)
        {
            if (!IsTextPreviewable(evidence.ContentType, evidence.OriginalFileName)) return null;
            var buffer = new byte[maxBytes];
            var read = 0;
            int n;
            while (read < maxBytes && (n = await stream.ReadAsync(buffer.AsMemory(read, maxBytes - read), ct)) > 0) read += n;
            if (buffer.AsSpan(0, read).IndexOf((byte)0) >= 0) return null;
            var text = System.Text.Encoding.UTF8.GetString(buffer, 0, read);
            // Keep line breaks and tabs; drop other control characters so nothing odd reaches the page.
            var clean = new System.Text.StringBuilder(text.Length);
            foreach (var ch in text)
                if (ch is '\n' or '\t' || !char.IsControl(ch)) clean.Append(ch);
            await RecordViewedAsync(evidenceId, ct);
            return read == maxBytes ? clean.ToString().TrimEnd() + "\n…" : clean.ToString();
        }
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
