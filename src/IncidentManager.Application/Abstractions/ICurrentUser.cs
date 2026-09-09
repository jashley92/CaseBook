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
    IReadOnlySet<AppRole> Roles { get; }
    bool IsInRole(AppRole role);

    /// <summary>The effective permissions granted by the user's roles.</summary>
    IReadOnlySet<Permission> Permissions { get; }

    /// <summary>Whether the user holds a given capability. The preferred authorization check.</summary>
    bool Has(Permission permission);
}
