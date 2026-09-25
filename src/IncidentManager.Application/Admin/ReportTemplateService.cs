using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>A library template for the admin list and the pickers.</summary>
public sealed record ReportTemplateView(
    Guid Id, string Name, string FileName, long SizeBytes, bool IsActive,
    DateTimeOffset UpdatedAtUtc, string UpdatedBy, IReadOnlyList<string> DefaultFor);

/// <summary>The outcome of an upload: the template check, and the new template's id when it was accepted.</summary>
public sealed record ReportTemplateUpload(Reporting.TemplateCheck Check, Guid? Id);

/// <summary>
/// The Word report template library (PROD-47). Admins upload several customer-designed templates; a report
/// profile names one as its default and whoever generates a Word report can pick another. Every upload is
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
        await store.SaveAsync(t.Id, docx, ct);
        db.ReportTemplates.Add(t);
        await db.SaveChangesAsync(ct);
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

        using var db = _factory.CreateDbContext();
        var t = await FindAsync(db, id, ct);
        await store.SaveAsync(id, docx, ct);
        t.FileName = Path.GetFileName(fileName);
        t.Sha256 = Sha256(docx);
        t.SizeBytes = docx.LongLength;
        t.ModifiedBy = _user.UserId;
        t.ModifiedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
        return check;
    }

    /// <summary>Renames a template, or archives/restores it. A profile's default can't be archived.</summary>
    public async Task UpdateAsync(Guid id, string name, bool isActive, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ReportTemplateService>(_user);
        var cleanName = RequireName(name);
        using var db = _factory.CreateDbContext();
        var t = await FindAsync(db, id, ct);
        await EnsureUniqueNameAsync(db, cleanName, id, ct);
        if (!isActive && t.IsActive)
            await EnsureNotADefaultAsync(db, id, "archive", ct);
        t.Name = cleanName;
        t.IsActive = isActive;
        t.ModifiedBy = _user.UserId;
        t.ModifiedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Deletes a template and its file. Reports already generated from it keep its name and hash.</summary>
    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ReportTemplateService>(_user);
        using var db = _factory.CreateDbContext();
        var t = await db.ReportTemplates.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (t is null) return;
        await EnsureNotADefaultAsync(db, id, "delete", ct);
        db.ReportTemplates.Remove(t);
        await db.SaveChangesAsync(ct);
        if (_store is not null) await _store.DeleteAsync(id, ct);
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
                defaults.Where(d => d.TemplateId == t.Id).Select(d => d.Name).OrderBy(n => n).ToList()))
            .ToList();
    }

    private static string Sha256(byte[] bytes) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
}
