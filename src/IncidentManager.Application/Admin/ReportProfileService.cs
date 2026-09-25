using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>A report profile resolved for the case picker and the admin editor.</summary>
public sealed record ReportProfileView(
    Guid Id, string Name, string? Description, bool IsActive, int SortOrder, string? SectionLayout,
    Guid? TemplateId = null, string? TemplateName = null);

/// <summary>The fields to create a report profile with, or replace an existing one's content.</summary>
public sealed record ReportProfileInput(
    string Name, string? Description, bool IsActive, int SortOrder, string? SectionLayout, Guid? TemplateId = null);

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
    public ReportProfileService(IAppDbContextFactory factory, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
    }

    /// <summary>Active profiles for the case picker, ordered for display.</summary>
    public async Task<List<ReportProfileView>> ListActiveAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await ProjectAsync(db, await Load(db).Where(p => p.IsActive).ToListAsync(ct), ct);
    }

    /// <summary>Every profile, active or not, for administration.</summary>
    public async Task<List<ReportProfileView>> ListAllAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await ProjectAsync(db, await Load(db).ToListAsync(ct), ct);
    }

    public async Task<ReportProfileView?> GetAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var p = await Load(db).FirstOrDefaultAsync(p => p.Id == id, ct);
        return p is null ? null : (await ProjectAsync(db, [p], ct))[0];
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
        await EnsureTemplateAsync(db, input.TemplateId, ct);
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

        await EnsureTemplateAsync(db, input.TemplateId, ct);
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
    }

    // A default template must exist and be active (archived templates can't be picked for new reports).
    private static async Task EnsureTemplateAsync(IAppDbContext db, Guid? templateId, CancellationToken ct)
    {
        if (templateId is not { } tid) return;
        if (!await db.ReportTemplates.AnyAsync(t => t.Id == tid && t.IsActive, ct))
            throw new InvalidOperationException("That Word template is archived or no longer exists. Pick another, or the built-in layout.");
    }

    private static void ApplyContent(ReportProfile p, ReportProfileInput input)
    {
        p.Description = Trim(input.Description);
        p.IsActive = input.IsActive;
        p.SortOrder = input.SortOrder;
        p.SectionLayout = Trim(input.SectionLayout);
        p.TemplateId = input.TemplateId;
    }

    private static IQueryable<ReportProfile> Load(IAppDbContext db) =>
        db.ReportProfiles.AsNoTracking().OrderBy(p => p.SortOrder).ThenBy(p => p.Name);

    private static async Task<List<ReportProfileView>> ProjectAsync(IAppDbContext db, List<ReportProfile> profiles, CancellationToken ct)
    {
        var ids = profiles.Where(p => p.TemplateId != null).Select(p => p.TemplateId!.Value).Distinct().ToList();
        var names = ids.Count == 0
            ? new Dictionary<Guid, string>()
            : await db.ReportTemplates.AsNoTracking().Where(t => ids.Contains(t.Id)).ToDictionaryAsync(t => t.Id, t => t.Name, ct);
        return profiles.Select(p => new ReportProfileView(p.Id, p.Name, p.Description, p.IsActive, p.SortOrder, p.SectionLayout,
            p.TemplateId, p.TemplateId is { } tid && names.TryGetValue(tid, out var n) ? n : null)).ToList();
    }

    private static string? Trim(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
