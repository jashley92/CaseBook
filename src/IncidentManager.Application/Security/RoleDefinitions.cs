using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Security;

/// <summary>
/// The built-in ("system") roles and the permissions each grants. These are the seeded, undeletable
/// roles that reproduce the app's original access model; custom roles (administered later) compose the
/// same <see cref="Permission"/> atoms. Keeping the definitions here means the app always has a working
/// role set even before any database-backed role customization exists.
/// </summary>
public static class RoleDefinitions
{
    public static readonly IReadOnlyDictionary<AppRole, Permission[]> SystemRoles = new Dictionary<AppRole, Permission[]>
    {
        [AppRole.Analyst] =
        [
            Permission.ViewCases, Permission.EditCases
        ],
        [AppRole.IncidentCommander] =
        [
            Permission.ViewCases, Permission.EditCases, Permission.ChangeClassification,
            Permission.ApproveReports, Permission.ViewRestricted
        ],
        [AppRole.Manager] =
        [
            Permission.ViewCases, Permission.ViewAllCases
        ],
        [AppRole.LegalPrivacy] =
        [
            Permission.ViewCases, Permission.ViewAllCases, Permission.ViewRestricted, Permission.ManageLegal
        ],
        // Administrators hold every permission, including future ones added to the enum.
        [AppRole.SysAdmin] = Enum.GetValues<Permission>(),
    };

    /// <summary>The union of permissions granted by the given system roles.</summary>
    public static IReadOnlySet<Permission> PermissionsFor(IEnumerable<AppRole> roles)
    {
        var set = new HashSet<Permission>();
        foreach (var role in roles)
            if (SystemRoles.TryGetValue(role, out var perms))
                set.UnionWith(perms);
        return set;
    }

    /// <summary>The union of permissions for role names (unparseable names are ignored).</summary>
    public static IReadOnlySet<Permission> PermissionsForRoleNames(IEnumerable<string> roleNames)
    {
        var roles = roleNames
            .Select(n => Enum.TryParse<AppRole>(n, ignoreCase: true, out var r) ? (AppRole?)r : null)
            .Where(r => r is not null)
            .Select(r => r!.Value);
        return PermissionsFor(roles);
    }
}
