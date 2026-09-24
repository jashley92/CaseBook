using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Abstractions;

/// <summary>The authenticated user for the current request/circuit, resolved from Windows auth.</summary>
public interface ICurrentUser
{
    /// <summary>Stable identifier (AD SID, or UPN as a fallback). "system" for background work.</summary>
    string UserId { get; }
    string DisplayName { get; }
    string? UserPrincipalName { get; }
    string? Email { get; }
    bool IsAuthenticated { get; }
    /// <summary>The built-in roles the user holds. Custom roles aren't here — see <see cref="RoleNames"/>.</summary>
    IReadOnlySet<AppRole> Roles { get; }
    bool IsInRole(AppRole role);

    /// <summary>
    /// S-14: every CaseBook role the user holds by name — built-in and custom — for display and for anything that
    /// compares roles (a personal API token may only carry the user's own roles). Defaults to the built-in set.
    /// </summary>
    IReadOnlyList<string> RoleNames => Roles.Select(r => r.ToString()).ToList();

    /// <summary>The effective permissions granted by the user's roles.</summary>
    IReadOnlySet<Permission> Permissions { get; }

    /// <summary>Whether the user holds a given capability. The preferred authorization check.</summary>
    bool Has(Permission permission);
}
