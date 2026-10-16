using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Abstractions;

/// <summary>
/// An in-memory, cached view of roles and AD-group→role mappings used during authentication to resolve
/// a user's roles and effective permissions without a database hit per request. Rebuilt on startup and
/// whenever roles/mappings are administered (<see cref="Invalidate"/>).
/// </summary>
public interface IRoleDirectory
{
    /// <summary>The union of permissions granted by the named roles (unknown names ignored).</summary>
    IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames);

    /// <summary>S-14: whether <paramref name="name"/> is a CaseBook role (built-in or custom), as opposed to, say, an
    /// AD group SID carried as a role claim.</summary>
    bool IsRole(string name) => PermissionsForRoles([name]).Count > 0;

    /// <summary>The role names granted to a user in the given AD security groups.</summary>
    IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups);

    /// <summary>BUG-609: the roles some mapping by group name (not by SID) grants: those a group whose name didn't come
    /// back in time could still be giving a user. Null when the directory can't say.</summary>
    IReadOnlySet<string>? RolesMappedByName => null;

    /// <summary>Rebuilds the cached snapshot from the database (call after any role/mapping change).</summary>
    void Invalidate();

    /// <summary>BUG-193: false while the last reload failed (and is being retried), so the snapshot still holds the
    /// roles and mappings from before the latest change.</summary>
    bool IsCurrent => true;
}
