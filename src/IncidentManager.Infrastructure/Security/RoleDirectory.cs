using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// Singleton cache of roles and AD-group→role mappings. Reads the database once (and again on
/// <see cref="Invalidate"/>) and answers authentication-time lookups from memory, so resolving a
/// user's permissions never costs a query per request. Tolerates a missing schema on first startup.
/// </summary>
public sealed class RoleDirectory : IRoleDirectory
{
    private readonly IServiceScopeFactory _scopes;
    private volatile Snapshot _snapshot = Snapshot.Empty;

    public RoleDirectory(IServiceScopeFactory scopes)
    {
        _scopes = scopes;
        Invalidate();
    }

    private sealed record Snapshot(
        IReadOnlyDictionary<string, IReadOnlySet<Permission>> RolePermissions,
        IReadOnlyDictionary<string, IReadOnlySet<string>> GroupRoles)
    {
        public static readonly Snapshot Empty = new(
            new Dictionary<string, IReadOnlySet<Permission>>(),
            new Dictionary<string, IReadOnlySet<string>>());
    }

    public void Invalidate()
    {
        try
        {
            using var scope = _scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            var roles = db.Roles.AsNoTracking().ToList();
            var maps = db.RoleMappings.AsNoTracking().ToList();

            var rolePermissions = roles.ToDictionary(
                r => r.Name,
                r => (IReadOnlySet<Permission>)Role.ParsePermissions(r.PermissionsCsv),
                StringComparer.OrdinalIgnoreCase);

            var groupRoles = maps
                .GroupBy(m => m.AdGroup, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    g => g.Key,
                    g => (IReadOnlySet<string>)g.Select(x => x.RoleName).ToHashSet(StringComparer.OrdinalIgnoreCase),
                    StringComparer.OrdinalIgnoreCase);

            _snapshot = new Snapshot(rolePermissions, groupRoles);
        }
        catch
        {
            // Schema not present yet (first run, pre-migration). The seeder calls Invalidate() again
            // once the database is ready; until then we resolve nothing.
        }
    }

    public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames)
    {
        var snap = _snapshot;
        var set = new HashSet<Permission>();
        foreach (var name in roleNames)
            if (snap.RolePermissions.TryGetValue(name, out var perms))
                set.UnionWith(perms);
        return set;
    }

    public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups)
    {
        var snap = _snapshot;
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in adGroups)
            if (snap.GroupRoles.TryGetValue(group, out var roles))
                set.UnionWith(roles);
        return set;
    }
}
