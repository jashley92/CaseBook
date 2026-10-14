using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>A report profile resolved for the case picker and the admin editor.</summary>
public sealed record ReportProfileView(
    Guid Id, string Name, string? Description, bool IsActive, int SortOrder, string? SectionLayout,
    Guid? TemplateId = null, string? TemplateName = null, string Stamp = "");

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
#pragma warning disable CA1304, CA1311, CA1862 // BUG-269: LOWER() on both sides, so SQLite matches as SQL Server does
        if (await db.ReportProfiles.AnyAsync(p => p.Name.ToLower() == name.ToLower(), ct))
#pragma warning restore CA1304, CA1311, CA1862
            throw new InvalidOperationException($"A report profile named '{name}' already exists. Choose a different name.");

        var profile = new ReportProfile { Name = name, CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow };
        await EnsureTemplateAsync(db, input.TemplateId, ct);
        ApplyContent(profile, input);
        db.ReportProfiles.Add(profile);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException ex)
        {
            // BUG-339: the same name was saved between the check above and this insert (the unique index refused it).
            using var check = _factory.CreateDbContext();
            if (await check.ReportProfiles.AnyAsync(p => p.Name == name, ct))
                throw new InvalidOperationException($"A report profile named '{name}' already exists. Choose a different name.", ex);
            throw;
        }
        return profile.Id;
    }

    /// <summary>REV-27 / BUG-349: <paramref name="expectedStamp"/> is the profile's <see cref="ReportProfileView.Stamp"/> when
    /// the editor opened; the edit replaces the whole profile, so one someone changed since is refused. Null skips the check.</summary>
    public async Task UpdateAsync(Guid id, ReportProfileInput input, string? expectedStamp = null, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ReportProfileService>(_user);
        using var db = _factory.CreateDbContext();
        var profile = await db.ReportProfiles.FirstOrDefaultAsync(p => p.Id == id, ct)
                      ?? throw new InvalidOperationException("That report profile no longer exists. Reload the page and try again.");
        if (expectedStamp is not null && !string.Equals(StampOf(profile), expectedStamp, StringComparison.Ordinal))
            throw new InvalidOperationException($"Someone changed the report profile \"{profile.Name}\" since you opened it, so nothing was saved: " +
                "it would have undone that. Reload the page, then make your change again.");

        var name = (input.Name ?? "").Trim();
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("A profile name is required.");
#pragma warning disable CA1304, CA1311, CA1862 // BUG-269: LOWER() on both sides, so SQLite matches as SQL Server does
        if (await db.ReportProfiles.AnyAsync(p => p.Name.ToLower() == name.ToLower() && p.Id != id, ct))
#pragma warning restore CA1304, CA1311, CA1862
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
            p.TemplateId, p.TemplateId is { } tid && names.TryGetValue(tid, out var n) ? n : null, StampOf(p))).ToList();
    }

    // BUG-349: the row hash, plus the Word template (PROD-47 kept it outside the hash): what the editor holds and writes back.
    private static string StampOf(ReportProfile p) => $"{p.RowHash}|{p.TemplateId}";

    private static string? Trim(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
