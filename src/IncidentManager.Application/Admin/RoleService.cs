using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>
/// Administers roles and AD-group→role mappings. System roles are locked (permissions owned by code);
/// custom roles compose the existing <see cref="Permission"/> atoms. Every change is audited and
/// hash-chained, then the in-memory <see cref="IRoleDirectory"/> is invalidated so it takes effect for
/// subsequent sign-ins. A safety guard prevents removing the last grant of <see cref="Permission.Administer"/>.
/// </summary>
public sealed class RoleService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly IRoleDirectory _directory;
    private readonly ISecurityEventSink? _siem;

    public RoleService(IAppDbContextFactory factory, ICurrentUser user, IClock clock, IRoleDirectory directory,
        ISecurityEventSink? siem = null)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _directory = directory;
        _siem = siem;
    }

    public async Task<List<Role>> ListRolesAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await db.Roles.AsNoTracking().OrderByDescending(r => r.IsSystem).ThenBy(r => r.Name).ToListAsync(ct);
    }

    public async Task<List<AdGroupRoleMapping>> ListMappingsAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await db.RoleMappings.AsNoTracking().OrderBy(m => m.AdGroup).ThenBy(m => m.RoleName).ToListAsync(ct);
    }

    public async Task CreateRoleAsync(string name, string? description, IEnumerable<Permission> permissions, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<RoleService>(_user, _siem);
        using var db = _factory.CreateDbContext();
        name = (name ?? "").Trim();
        if (Role.NameProblem(name) is { } problem) throw new ArgumentException(problem);
        // BUG-18: role names are matched regardless of case everywhere else, so "sysadmin" is SysAdmin.
        var lower = name.ToLowerInvariant();
#pragma warning disable CA1304, CA1311, CA1862 // EF Core translates ToLower() to SQL LOWER(); the invariant overload doesn't translate.
        if (await db.Roles.AnyAsync(r => r.Name.ToLower() == lower, ct))
#pragma warning restore CA1304, CA1311, CA1862
            throw new InvalidOperationException($"A role named '{name}' already exists. Choose a different name.");

        var role = new Role { Name = name, Description = description?.Trim(), IsSystem = false };
        role.SetPermissions(permissions, _user.UserId, _clock.UtcNow);

        db.Roles.Add(role);
        await db.SaveChangesAsync(ct);
        _directory.Invalidate();
        _siem?.Emit(SecurityEvents.RoleChanged("RoleCreated", _user.UserId, _user.UserPrincipalName, name));
    }

    /// <summary>BUG-193: false when the last change is saved but the role directory couldn't reload it yet (it keeps
    /// retrying), so permissions still follow the previous roles and mappings.</summary>
    public bool ChangesInEffect => _directory.IsCurrent;

    /// <summary>What to tell the admin when <see cref="ChangesInEffect"/> is false.</summary>
    public const string NotInEffectMessage = "Saved, but not in effect yet: CaseBook couldn't reload roles from the database, " +
        "so people still have the permissions they had before. It keeps retrying; check the application log.";

    /// <summary>REV-27: <paramref name="expectedStamp"/> is the role's row hash when the editor opened. The edit writes the
    /// whole permission set back, so a role someone changed since (taking ViewRestricted off, say) is refused rather than
    /// quietly restored. Null skips the check.</summary>
    public async Task UpdateRoleAsync(Guid id, string? description, IEnumerable<Permission> permissions,
        string? expectedStamp = null, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<RoleService>(_user, _siem);
        using var db = _factory.CreateDbContext();
        var role = await db.Roles.FirstOrDefaultAsync(r => r.Id == id, ct)
                   ?? throw new InvalidOperationException("That role no longer exists. Reload the page and try again.");
        if (role.IsSystem) throw new InvalidOperationException("System roles can't be edited. Create a custom role instead.");
        if (expectedStamp is not null && !string.Equals(role.RowHash ?? "", expectedStamp, StringComparison.Ordinal))
            throw new InvalidOperationException($"Someone changed the role \"{role.Name}\" since you opened it, so nothing was saved: " +
                "it would have undone that. Reload the page, then make your change again.");

        // S-17: the same anti-lockout guard as delete — taking Administer off a role mustn't remove the last admin access.
        var perms = permissions as IReadOnlyCollection<Permission> ?? permissions.ToList();
        permissions = perms;
        if (role.GetPermissions().Contains(Permission.Administer) && !perms.Contains(Permission.Administer)
            && !await AdministerRemainsWithoutAsync(db, roleName: role.Name, exceptMappingId: null, ct))
            throw new InvalidOperationException("Can't remove Administer: this role holds the last administrator access. Grant Administer to another role first.");

        role.Description = description?.Trim();
        role.SetPermissions(permissions, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
        _directory.Invalidate();
        _siem?.Emit(SecurityEvents.RoleChanged("RoleUpdated", _user.UserId, _user.UserPrincipalName, role.Name));
    }

    public async Task DeleteRoleAsync(Guid id, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<RoleService>(_user, _siem);
        using var db = _factory.CreateDbContext();
        var role = await db.Roles.FirstOrDefaultAsync(r => r.Id == id, ct)
                   ?? throw new InvalidOperationException("That role no longer exists. Reload the page and try again.");
        if (role.IsSystem) throw new InvalidOperationException("System roles can't be deleted.");

        if (role.GetPermissions().Contains(Permission.Administer)
            && !await AdministerRemainsWithoutAsync(db, roleName: role.Name, exceptMappingId: null, ct))
            throw new InvalidOperationException("Can't delete this role: it holds the last administrator access. Grant Administer to another role first.");

        // WF-56: an active API token that holds the role would pick up a later role of the same name, so the role can't be
        // deleted while one does (owner's decision): revoke the tokens or change their roles first.
        var now = _clock.UtcNow;
        var holders = (await db.ApiTokens.AsNoTracking().Where(t => t.RevokedAtUtc == null).ToListAsync(ct))
            .Where(t => t.IsActive(now) && t.GetRoles().Contains(role.Name, StringComparer.OrdinalIgnoreCase))
            .Select(t => t.Name).OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
        if (holders.Count > 0)
            throw new InvalidOperationException($"Can't delete this role: active API tokens hold it ({string.Join(", ", holders)}). " +
                                                "Revoke them or change their roles first.");

        // WF-46: every mapping to it, whatever the casing (SQLite compares case-sensitively; role names match ignoring case).
        var lower = role.Name.ToLowerInvariant();
#pragma warning disable CA1304, CA1311, CA1862 // translated to SQL LOWER()
        var mappings = await db.RoleMappings.Where(m => m.RoleName.ToLower() == lower).ToListAsync(ct);
#pragma warning restore CA1304, CA1311, CA1862
        db.RoleMappings.RemoveRange(mappings);
        db.Roles.Remove(role);
        await db.SaveChangesAsync(ct);
        _directory.Invalidate();
        _siem?.Emit(SecurityEvents.RoleChanged("RoleDeleted", _user.UserId, _user.UserPrincipalName, role.Name));
    }

    public async Task AddMappingAsync(string adGroup, string roleName, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<RoleService>(_user, _siem);
        using var db = _factory.CreateDbContext();
        adGroup = (adGroup ?? "").Trim();
        roleName = (roleName ?? "").Trim();
        if (string.IsNullOrWhiteSpace(adGroup)) throw new ArgumentException("An AD group is required.");
        var roleLower = roleName.ToLowerInvariant();
#pragma warning disable CA1304, CA1311, CA1862 // as above: translated to SQL LOWER()
        var role = await db.Roles.AsNoTracking().FirstOrDefaultAsync(r => r.Name.ToLower() == roleLower, ct)
                   ?? throw new InvalidOperationException($"No role named '{roleName}'. Reload the page and choose another.");
#pragma warning restore CA1304, CA1311, CA1862
        roleName = role.Name;   // BUG-18: store the role's own spelling
        if (await db.RoleMappings.AnyAsync(m => m.AdGroup == adGroup && m.RoleName == roleName, ct))
            throw new InvalidOperationException("That mapping already exists.");

        db.RoleMappings.Add(new AdGroupRoleMapping
        {
            AdGroup = adGroup,
            RoleName = roleName,
            UpdatedAtUtc = _clock.UtcNow,
            UpdatedBy = _user.UserId
        });
        await db.SaveChangesAsync(ct);
        _directory.Invalidate();
        _siem?.Emit(SecurityEvents.MappingChanged("AdGroupMappingAdded", _user.UserId, _user.UserPrincipalName, $"{adGroup} → {roleName}"));
    }

    public async Task RemoveMappingAsync(Guid id, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<RoleService>(_user, _siem);
        using var db = _factory.CreateDbContext();
        var mapping = await db.RoleMappings.FirstOrDefaultAsync(m => m.Id == id, ct);
        if (mapping is null) return;

        if (!await AdministerRemainsWithoutAsync(db, roleName: null, exceptMappingId: id, ct))
            throw new InvalidOperationException("Can't remove this mapping: it grants the last administrator access. Map another group to an admin role first.");

        db.RoleMappings.Remove(mapping);
        await db.SaveChangesAsync(ct);
        _directory.Invalidate();
        _siem?.Emit(SecurityEvents.MappingChanged("AdGroupMappingRemoved", _user.UserId, _user.UserPrincipalName, $"{mapping.AdGroup} → {mapping.RoleName}"));
    }

    /// <summary>
    /// True if, after excluding a mapping (and/or a role about to be deleted), some remaining AD-group
    /// mapping still grants a role that holds <see cref="Permission.Administer"/> — the anti-lockout check.
    /// </summary>
    private static async Task<bool> AdministerRemainsWithoutAsync(IAppDbContext db, string? roleName, Guid? exceptMappingId, CancellationToken ct)
    {
        var adminRoles = (await db.Roles.AsNoTracking().ToListAsync(ct))
            .Where(r => r.GetPermissions().Contains(Permission.Administer)
                        && !string.Equals(r.Name, roleName, StringComparison.OrdinalIgnoreCase))
            .Select(r => r.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (adminRoles.Count == 0) return false;

        var mappings = await db.RoleMappings.AsNoTracking()
            .Where(m => exceptMappingId == null || m.Id != exceptMappingId)
            .ToListAsync(ct);

        return mappings.Any(m => adminRoles.Contains(m.RoleName));
    }
}
