using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>A library template for the admin list and the pickers.</summary>
public sealed record ReportTemplateView(
    Guid Id, string Name, string FileName, long SizeBytes, bool IsActive,
    DateTimeOffset UpdatedAtUtc, string UpdatedBy, IReadOnlyList<string> DefaultFor, bool IsLessonsDefault = false);

/// <summary>The outcome of an upload: the template check, and the new template's id when it was accepted.</summary>
public sealed record ReportTemplateUpload(Reporting.TemplateCheck Check, Guid? Id);

/// <summary>
/// The Word report template library (PROD-47). Admins upload several customer-designed templates; a report
/// profile names one as its default, one can be the lessons-learned reports' default, and whoever generates a
/// report can pick another. Any template can fill either report and use any field. Every upload is
/// checked (a plain .docx with no macros, embedded objects or externally loaded content, using only known
/// placeholders) before anything is stored. Reads are open to case editors (the Report tab picker); writes
/// are admin-only. Changes are audited and hash-chained by the save interceptor.
/// </summary>
public sealed class ReportTemplateService
{
    /// <summary>The largest Word template accepted.</summary>
    public const int MaxTemplateBytes = 5 * 1024 * 1024;

    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly Reporting.IReportTemplateEngine? _engine;
    private readonly Reporting.IReportTemplateStore? _store;

    public ReportTemplateService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        Reporting.IReportTemplateEngine? engine = null, Reporting.IReportTemplateStore? store = null)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _engine = engine;
        _store = store;
    }

    /// <summary>Every template, archived ones included, for administration. Ordered by name.</summary>
    public async Task<List<ReportTemplateView>> ListAllAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await ProjectAsync(db, await db.ReportTemplates.AsNoTracking().ToListAsync(ct), ct);
    }

    /// <summary>Templates that can be picked for a new report, ordered by name.</summary>
    public async Task<List<ReportTemplateView>> ListActiveAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await ProjectAsync(db, await db.ReportTemplates.AsNoTracking().Where(t => t.IsActive).ToListAsync(ct), ct);
    }

    /// <summary>Checks and stores a new template. Nothing is stored unless the check passes.</summary>
    public async Task<ReportTemplateUpload> UploadAsync(string name, string fileName, byte[] docx, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ReportTemplateService>(_user);
        var (engine, store) = Ready();
        var cleanName = RequireName(name);
        ValidateFile(fileName, docx);

        var check = engine.Check(docx);
        if (!check.Ok) return new ReportTemplateUpload(check, null);

        using var db = _factory.CreateDbContext();
        await EnsureUniqueNameAsync(db, cleanName, null, ct);
        var t = new ReportTemplate
        {
            Name = cleanName,
            FileName = Path.GetFileName(fileName),
            Sha256 = Sha256(docx),
            SizeBytes = docx.LongLength,
            CreatedBy = _user.UserId,
            CreatedAtUtc = _clock.UtcNow,
        };
        await FileGate.WaitAsync(ct);
        try
        {
            var staged = await store.StageAsync(t.Id, docx, ct);   // BUG-199: in place only once the row is saved
            db.ReportTemplates.Add(t);
            await SaveThenCommitAsync(db, store, staged, () => db.ReportTemplates.Remove(t), ct);
        }
        finally { FileGate.Release(); }
        return new ReportTemplateUpload(check, t.Id);
    }

    /// <summary>Replaces a template's file (keeping its name and the profiles that use it). Checked first.</summary>
    public async Task<Reporting.TemplateCheck> ReplaceFileAsync(Guid id, string fileName, byte[] docx, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ReportTemplateService>(_user);
        var (engine, store) = Ready();
        ValidateFile(fileName, docx);

        var check = engine.Check(docx);
        if (!check.Ok) return check;

        // BUG-239: one file write at a time, so two replaces can't save in one order and move their files in the other.
        await FileGate.WaitAsync(ct);
        try
        {
            using var db = _factory.CreateDbContext();
            var t = await FindAsync(db, id, ct);
            var staged = await store.StageAsync(id, docx, ct);   // BUG-199: the live file stays until the new hash is saved
            var (oldName, oldHash, oldSize, oldBy, oldAt) = (t.FileName, t.Sha256, t.SizeBytes, t.ModifiedBy, t.ModifiedAtUtc);
            t.FileName = Path.GetFileName(fileName);
            t.Sha256 = Sha256(docx);
            t.SizeBytes = docx.LongLength;
            t.ModifiedBy = _user.UserId;
            t.ModifiedAtUtc = _clock.UtcNow;
            await SaveThenCommitAsync(db, store, staged,
                () => (t.FileName, t.Sha256, t.SizeBytes, t.ModifiedBy, t.ModifiedAtUtc) = (oldName, oldHash, oldSize, oldBy, oldAt), ct);
        }
        finally { FileGate.Release(); }
        return check;
    }

    private static readonly SemaphoreSlim FileGate = new(1, 1);

    /// <summary>
    /// BUG-403: the template file gate, for another writer of template files (a config import), so its staging and commit
    /// can't interleave with an upload or replace. Taken after <see cref="GuardGate"/>, never before it (nothing here takes
    /// GuardGate). Dispose the result to release it.
    /// </summary>
    public static async Task<IDisposable> EnterFileGateAsync(CancellationToken ct = default)
    {
        await FileGate.WaitAsync(ct).ConfigureAwait(false);
        return new FileGateReleaser();
    }

    private sealed class FileGateReleaser : IDisposable
    {
        private int _released;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0) FileGate.Release();
        }
    }

    // BUG-239: the row is saved first, then the file moved into place. If the move fails for good (the file read-only,
    // no permission), the row is put back as it was (undo) and the staged file removed, so "nothing changed" is true:
    // the row never describes a file that isn't the live one (which would refuse every report from the template).
    private static async Task SaveThenCommitAsync(IAppDbContext db, Reporting.IReportTemplateStore store, Reporting.StagedTemplate staged,
        Action undo, CancellationToken ct)
    {
        try { await db.SaveChangesAsync(ct); }
        catch
        {
            await store.DiscardAsync(staged);
            throw;
        }
        try { await store.CommitAsync(staged, ct); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try { await store.DiscardAsync(staged); } catch (Exception d) when (d is IOException or UnauthorizedAccessException) { }
            undo();
            await db.SaveChangesAsync(CancellationToken.None);
            throw;
        }
    }

    // BUG-350: rename and archive/restore are separate writes. One UpdateAsync(name, isActive) took the other field from
    // the page, so renaming on a stale page restored an archived template, and archiving put back an old name.

    /// <summary>Renames a template. Its active flag is left as it is.</summary>
    public async Task RenameAsync(Guid id, string name, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ReportTemplateService>(_user);
        var cleanName = RequireName(name);
        using var db = _factory.CreateDbContext();
        var t = await FindAsync(db, id, ct);
        await EnsureUniqueNameAsync(db, cleanName, id, ct);
        t.Name = cleanName;
        t.ModifiedBy = _user.UserId;
        t.ModifiedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Archives or restores a template. Its name is left as it is. A profile's default can't be archived.</summary>
    public async Task SetActiveAsync(Guid id, bool isActive, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ReportTemplateService>(_user);
        using var db = _factory.CreateDbContext();
        var t = await FindAsync(db, id, ct);
        if (!isActive && t.IsActive)
            await EnsureNotADefaultAsync(db, id, "archive", ct);
        t.IsActive = isActive;
        t.ModifiedBy = _user.UserId;
        t.ModifiedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Makes a template the default for lessons-learned reports (clearing any previous one), or stops it being the
    /// default. Only an active template can be the default.
    /// </summary>
    public async Task SetLessonsDefaultAsync(Guid id, bool isDefault, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ReportTemplateService>(_user);
        using var db = _factory.CreateDbContext();
        var t = await FindAsync(db, id, ct);
        if (isDefault && !t.IsActive)
            throw new InvalidOperationException("Restore the template before making it the lessons-learned default.");
        if (isDefault)
            foreach (var other in await db.ReportTemplates.Where(x => x.IsLessonsDefault && x.Id != id).ToListAsync(ct))
            {
                other.IsLessonsDefault = false;
                other.ModifiedBy = _user.UserId;
                other.ModifiedAtUtc = _clock.UtcNow;
            }
        if (t.IsLessonsDefault == isDefault) { await db.SaveChangesAsync(ct); return; }
        t.IsLessonsDefault = isDefault;
        t.ModifiedBy = _user.UserId;
        t.ModifiedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Deletes a template and its file. Reports already generated from it keep its name and hash.</summary>
    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ReportTemplateService>(_user);
        using var files = await EnterFileGateAsync(ct);   // BUG-403: not between another writer's save and its file move
        using var db = _factory.CreateDbContext();
        var t = await db.ReportTemplates.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (t is null) return;
        await EnsureNotADefaultAsync(db, id, "delete", ct);
        db.ReportTemplates.Remove(t);
        await db.SaveChangesAsync(ct);
        // BUG-239: the template is deleted once its row is; a file that can't be removed now (open, read-only) is left
        // unreferenced rather than reported as a failed delete.
        if (_store is not null)
            try { await _store.DeleteAsync(id, ct); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>A template's file, for an admin to download and edit, or null.</summary>
    public async Task<(string FileName, byte[] Bytes)?> GetFileAsync(Guid id, CancellationToken ct = default)
    {
        if (_store is null) return null;
        using var db = _factory.CreateDbContext();
        var name = await db.ReportTemplates.AsNoTracking().Where(t => t.Id == id).Select(t => t.FileName).FirstOrDefaultAsync(ct);
        if (name is null) return null;
        var bytes = await _store.GetAsync(id, ct);
        return bytes is null ? null : (name, bytes);
    }

    private (Reporting.IReportTemplateEngine, Reporting.IReportTemplateStore) Ready() =>
        _engine is not null && _store is not null
            ? (_engine, _store)
            : throw new InvalidOperationException("Word templates aren't available on this server.");

    private static string RequireName(string? name)
    {
        var n = (name ?? "").Trim();
        if (n.Length == 0) throw new ArgumentException("Give the template a name, for example \"Examiner pack\".");
        if (n.Length > 200) throw new ArgumentException("A template name can be at most 200 characters.");
        return n;
    }

    private static void ValidateFile(string fileName, byte[] docx)
    {
        if (docx.Length == 0) throw new ArgumentException("That file is empty. Choose a .docx template.");
        if (docx.Length > MaxTemplateBytes) throw new ArgumentException($"A template must be {MaxTemplateBytes / 1024 / 1024} MB or smaller.");
        if (!fileName.EndsWith(".docx", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Upload a Word document (.docx). Macro-enabled files (.docm) aren't accepted.");
    }

    private static async Task EnsureUniqueNameAsync(IAppDbContext db, string name, Guid? exceptId, CancellationToken ct)
    {
        var lower = name.ToLowerInvariant();
#pragma warning disable CA1304, CA1311, CA1862 // translated to SQL LOWER(); culture-invariant enough for a name check
        if (await db.ReportTemplates.AnyAsync(t => t.Name.ToLower() == lower && (exceptId == null || t.Id != exceptId), ct))
#pragma warning restore CA1304, CA1311, CA1862
            throw new InvalidOperationException($"A template named \"{name}\" already exists. Choose a different name.");
    }

    private static async Task EnsureNotADefaultAsync(IAppDbContext db, Guid id, string verb, CancellationToken ct)
    {
        if (await db.ReportTemplates.AnyAsync(t => t.Id == id && t.IsLessonsDefault, ct))
            throw new InvalidOperationException(
                $"Can't {verb} it: it's the default for lessons-learned reports. Make another template the lessons-learned default, or stop using this one for them, first.");
        var users = await db.ReportProfiles.AsNoTracking().Where(p => p.TemplateId == id).Select(p => p.Name).ToListAsync(ct);
        if (users.Count > 0)
            throw new InvalidOperationException(
                $"Can't {verb} it: it's the default for {string.Join(", ", users.Select(u => $"\"{u}\""))}. Pick another template for {(users.Count == 1 ? "that profile" : "those profiles")} first.");
    }

    private static async Task<ReportTemplate> FindAsync(IAppDbContext db, Guid id, CancellationToken ct) =>
        await db.ReportTemplates.FirstOrDefaultAsync(t => t.Id == id, ct)
        ?? throw new InvalidOperationException("That template no longer exists. Reload the page and try again.");

    private static async Task<List<ReportTemplateView>> ProjectAsync(IAppDbContext db, List<ReportTemplate> templates, CancellationToken ct)
    {
        var defaults = await db.ReportProfiles.AsNoTracking().Where(p => p.TemplateId != null)
            .Select(p => new { p.TemplateId, p.Name }).ToListAsync(ct);
        return templates
            .OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
            .Select(t => new ReportTemplateView(t.Id, t.Name, t.FileName, t.SizeBytes, t.IsActive,
                t.ModifiedAtUtc ?? t.CreatedAtUtc, t.ModifiedBy ?? t.CreatedBy,
                defaults.Where(d => d.TemplateId == t.Id).Select(d => d.Name).OrderBy(n => n)
                    .Concat(t.IsLessonsDefault ? ["Lessons-learned reports"] : []).ToList(),
                t.IsLessonsDefault))
            .ToList();
    }

    private static string Sha256(byte[] bytes) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
}
