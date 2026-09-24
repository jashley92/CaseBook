using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>A report profile resolved for the case picker and the admin editor.</summary>
public sealed record ReportProfileView(
    Guid Id, string Name, string? Description, bool IsActive, int SortOrder, string? SectionLayout,
    string? TemplateFileName = null);

/// <summary>The fields to create a report profile with, or replace an existing one's content.</summary>
public sealed record ReportProfileInput(
    string Name, string? Description, bool IsActive, int SortOrder, string? SectionLayout);

/// <summary>
/// Administers report profiles (E-28): named, reusable report section layouts a case can be printed with
/// (e.g. "Executive summary" vs "Full examiner pack"). Reads are open to case editors (they drive the
/// per-case profile picker on the Report tab); writes are admin-only and gated at the web layer. Every
/// change is audited and hash-chained by the save interceptor like other reference data.
/// </summary>
public sealed class ReportProfileService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly Reporting.IReportTemplateEngine? _templates;
    private readonly Reporting.IReportTemplateStore? _templateStore;

    /// <summary>PROD-47: the largest Word template accepted.</summary>
    public const int MaxTemplateBytes = 5 * 1024 * 1024;

    public ReportProfileService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        Reporting.IReportTemplateEngine? templates = null, Reporting.IReportTemplateStore? templateStore = null)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _templates = templates;
        _templateStore = templateStore;
    }

    /// <summary>
    /// PROD-47: attaches a customer-designed Word template to a profile, after checking it (a plain .docx — no
    /// macros, embedded objects or externally loaded content — using only known placeholders). Returns the check;
    /// nothing is stored unless it passes.
    /// </summary>
    public async Task<Reporting.TemplateCheck> UploadTemplateAsync(Guid id, string fileName, byte[] docx, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ReportProfileService>(_user);
        if (_templates is null || _templateStore is null) throw new InvalidOperationException("Word templates aren't available on this server.");
        if (docx.Length == 0) throw new ArgumentException("That file is empty. Choose a .docx template.");
        if (docx.Length > MaxTemplateBytes) throw new ArgumentException($"A template must be {MaxTemplateBytes / 1024 / 1024} MB or smaller.");
        if (!fileName.EndsWith(".docx", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Upload a Word document (.docx). Macro-enabled files (.docm) aren't accepted.");

        var check = _templates.Check(docx);
        if (!check.Ok) return check;

        using var db = _factory.CreateDbContext();
        var profile = await db.ReportProfiles.FirstOrDefaultAsync(p => p.Id == id, ct)
                      ?? throw new InvalidOperationException("That report profile no longer exists. Reload the page and try again.");
        await _templateStore.SaveAsync(id, docx, ct);
        profile.TemplateFileName = Path.GetFileName(fileName);
        profile.TemplateSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(docx)).ToLowerInvariant();
        profile.ModifiedBy = _user.UserId;
        profile.ModifiedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
        return check;
    }

    /// <summary>PROD-47: detaches the template, so the profile's Word reports use the built-in layout again.</summary>
    public async Task RemoveTemplateAsync(Guid id, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ReportProfileService>(_user);
        using var db = _factory.CreateDbContext();
        var profile = await db.ReportProfiles.FirstOrDefaultAsync(p => p.Id == id, ct)
                      ?? throw new InvalidOperationException("That report profile no longer exists. Reload the page and try again.");
        if (profile.TemplateFileName is null) return;
        profile.TemplateFileName = null;
        profile.TemplateSha256 = null;
        profile.ModifiedBy = _user.UserId;
        profile.ModifiedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
        if (_templateStore is not null) await _templateStore.DeleteAsync(id, ct);
    }

    /// <summary>PROD-47: the profile's uploaded template file (for an admin to download and edit), or null.</summary>
    public async Task<(string FileName, byte[] Bytes)?> GetTemplateAsync(Guid id, CancellationToken ct = default)
    {
        if (_templateStore is null) return null;
        using var db = _factory.CreateDbContext();
        var name = await db.ReportProfiles.AsNoTracking().Where(p => p.Id == id).Select(p => p.TemplateFileName).FirstOrDefaultAsync(ct);
        if (name is null) return null;
        var bytes = await _templateStore.GetAsync(id, ct);
        return bytes is null ? null : (name, bytes);
    }

    /// <summary>Active profiles for the case picker, ordered for display.</summary>
    public async Task<List<ReportProfileView>> ListActiveAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return Project(await Load(db).Where(p => p.IsActive).ToListAsync(ct));
    }

    /// <summary>Every profile, active or not, for administration.</summary>
    public async Task<List<ReportProfileView>> ListAllAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return Project(await Load(db).ToListAsync(ct));
    }

    public async Task<ReportProfileView?> GetAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var p = await Load(db).FirstOrDefaultAsync(p => p.Id == id, ct);
        return p is null ? null : Project(p);
    }

    public async Task<Guid> CreateAsync(ReportProfileInput input, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ReportProfileService>(_user);
        using var db = _factory.CreateDbContext();
        var name = (input.Name ?? "").Trim();
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("A profile name is required.");
        if (await db.ReportProfiles.AnyAsync(p => p.Name == name, ct))
            throw new InvalidOperationException($"A report profile named '{name}' already exists. Choose a different name.");

        var profile = new ReportProfile { Name = name, CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow };
        ApplyContent(profile, input);
        db.ReportProfiles.Add(profile);
        await db.SaveChangesAsync(ct);
        return profile.Id;
    }

    public async Task UpdateAsync(Guid id, ReportProfileInput input, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ReportProfileService>(_user);
        using var db = _factory.CreateDbContext();
        var profile = await db.ReportProfiles.FirstOrDefaultAsync(p => p.Id == id, ct)
                      ?? throw new InvalidOperationException("That report profile no longer exists. Reload the page and try again.");

        var name = (input.Name ?? "").Trim();
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("A profile name is required.");
        if (await db.ReportProfiles.AnyAsync(p => p.Name == name && p.Id != id, ct))
            throw new InvalidOperationException($"A report profile named '{name}' already exists. Choose a different name.");

        profile.Name = name;
        profile.ModifiedBy = _user.UserId;
        profile.ModifiedAtUtc = _clock.UtcNow;
        ApplyContent(profile, input);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Deletes a profile. Cases that referenced it keep the (now-dangling) id and simply fall back to the
    /// global default layout when their report is next generated/previewed — the resolver tolerates a
    /// missing/inactive profile — so no case update is needed here.
    /// </summary>
    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ReportProfileService>(_user);
        using var db = _factory.CreateDbContext();
        var profile = await db.ReportProfiles.FirstOrDefaultAsync(p => p.Id == id, ct);
        if (profile is null) return;
        db.ReportProfiles.Remove(profile);
        await db.SaveChangesAsync(ct);
        if (_templateStore is not null) await _templateStore.DeleteAsync(id, ct);   // PROD-47
    }

    private static void ApplyContent(ReportProfile p, ReportProfileInput input)
    {
        p.Description = Trim(input.Description);
        p.IsActive = input.IsActive;
        p.SortOrder = input.SortOrder;
        p.SectionLayout = Trim(input.SectionLayout);
    }

    private static IQueryable<ReportProfile> Load(IAppDbContext db) =>
        db.ReportProfiles.AsNoTracking().OrderBy(p => p.SortOrder).ThenBy(p => p.Name);

    private static List<ReportProfileView> Project(IEnumerable<ReportProfile> profiles) =>
        profiles.Select(Project).ToList();

    private static ReportProfileView Project(ReportProfile p) =>
        new(p.Id, p.Name, p.Description, p.IsActive, p.SortOrder, p.SectionLayout, p.TemplateFileName);

    private static string? Trim(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
