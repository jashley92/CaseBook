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
        using var db = _factory.CreateDbContext();
        name = (name ?? "").Trim();
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("A role name is required.");
        if (await db.Roles.AnyAsync(r => r.Name == name, ct))
            throw new InvalidOperationException($"A role named '{name}' already exists.");

        var role = new Role { Name = name, Description = description?.Trim(), IsSystem = false };
        role.SetPermissions(permissions, _user.UserId, _clock.UtcNow);

        db.Roles.Add(role);
        await db.SaveChangesAsync(ct);
        _directory.Invalidate();
        _siem?.Emit(SecurityEvents.RoleChanged("RoleCreated", _user.UserId, _user.UserPrincipalName, name));
    }

    public async Task UpdateRoleAsync(Guid id, string? description, IEnumerable<Permission> permissions, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var role = await db.Roles.FirstOrDefaultAsync(r => r.Id == id, ct)
                   ?? throw new InvalidOperationException("Role not found.");
        if (role.IsSystem) throw new InvalidOperationException("System roles are managed in code and cannot be edited.");

        role.Description = description?.Trim();
        role.SetPermissions(permissions, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
        _directory.Invalidate();
        _siem?.Emit(SecurityEvents.RoleChanged("RoleUpdated", _user.UserId, _user.UserPrincipalName, role.Name));
    }

    public async Task DeleteRoleAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var role = await db.Roles.FirstOrDefaultAsync(r => r.Id == id, ct)
                   ?? throw new InvalidOperationException("Role not found.");
        if (role.IsSystem) throw new InvalidOperationException("System roles cannot be deleted.");

        if (role.GetPermissions().Contains(Permission.Administer)
            && !await AdministerRemainsWithoutAsync(db, roleName: role.Name, exceptMappingId: null, ct))
            throw new InvalidOperationException("Deleting this role would remove the last administrator access.");

        var mappings = await db.RoleMappings.Where(m => m.RoleName == role.Name).ToListAsync(ct);
        db.RoleMappings.RemoveRange(mappings);
        db.Roles.Remove(role);
        await db.SaveChangesAsync(ct);
        _directory.Invalidate();
        _siem?.Emit(SecurityEvents.RoleChanged("RoleDeleted", _user.UserId, _user.UserPrincipalName, role.Name));
    }

    public async Task AddMappingAsync(string adGroup, string roleName, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        adGroup = (adGroup ?? "").Trim();
        roleName = (roleName ?? "").Trim();
        if (string.IsNullOrWhiteSpace(adGroup)) throw new ArgumentException("An AD group is required.");
        if (!await db.Roles.AnyAsync(r => r.Name == roleName, ct))
            throw new InvalidOperationException($"No role named '{roleName}'.");
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
        using var db = _factory.CreateDbContext();
        var mapping = await db.RoleMappings.FirstOrDefaultAsync(m => m.Id == id, ct);
        if (mapping is null) return;

        if (!await AdministerRemainsWithoutAsync(db, roleName: null, exceptMappingId: id, ct))
            throw new InvalidOperationException("Removing this mapping would remove the last administrator access.");

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
