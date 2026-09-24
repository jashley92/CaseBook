using System.Security.Claims;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Web.Security;

/// <summary>
/// S-10: re-derives a signed-in principal's CaseBook roles and permissions from the <em>current</em> role directory.
/// A Blazor circuit keeps the principal it started with, so without this an admin removing an AD-group mapping,
/// deleting a role or editing its permissions only reached open sessions when they reconnected. Windows sign-in:
/// roles come from the user's AD groups (the group SIDs/names on the Windows identity) through the current mappings.
/// Dev sign-in: the configured roles stay, their permissions are re-read. AD group membership itself only changes
/// with a new Windows logon — that's the OS token, not something an app can refresh.
/// </summary>
public sealed class SessionPermissionRefresher
{
    private readonly Func<IRoleDirectory> _directoryFactory;
    private readonly bool _windowsMode;

    public SessionPermissionRefresher(IRoleDirectory directory, bool windowsMode)
        : this(() => directory, windowsMode) { }

    /// <param name="directory">
    /// Resolved on first use: the directory loads itself through a DbContext whose audit interceptor needs the current
    /// user, whose auth-state provider needs this — taking it eagerly deadlocks the container at startup (as S-14 found).
    /// </param>
    public SessionPermissionRefresher(Func<IRoleDirectory> directory, bool windowsMode)
    {
        _directoryFactory = directory;
        _windowsMode = windowsMode;
    }

    private IRoleDirectory Directory => _directoryFactory();

    /// <summary>
    /// The principal with its roles and permissions brought up to date, or <c>null</c> when nothing changed (so the
    /// caller doesn't churn the auth state). Identity claims (name, SID, UPN, groups) are kept as they were.
    /// </summary>
    public ClaimsPrincipal? Refresh(ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated != true) return null;

        var heldRoles = AppRoleClaims(principal).Select(c => c.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var heldPerms = principal.FindAll(AppClaimTypes.Permission).Select(c => c.Value).ToHashSet(StringComparer.Ordinal);

        IReadOnlySet<string> roles = _windowsMode
            ? Directory.RolesForGroups(RoleClaimsTransformer.GroupCandidates(principal))
            : heldRoles;
        var perms = Directory.PermissionsForRoles(roles);
        if (!_windowsMode && perms.Count == 0) perms = RoleDefinitions.PermissionsForRoleNames(roles); // dev fallback
        var permNames = perms.Select(p => p.ToString()).ToHashSet(StringComparer.Ordinal);

        if (heldRoles.SetEquals(roles) && heldPerms.SetEquals(permNames)) return null;

        // Keep each authenticated identity minus the app-role and permission claims, then add the current ones.
        var identities = principal.Identities
            .Where(i => i.IsAuthenticated)
            .Select(i => new ClaimsIdentity(
                i.Claims.Where(c => c.Type != AppClaimTypes.Permission && !IsAppRoleClaim(c)).Select(c => c.Clone()),
                i.AuthenticationType, i.NameClaimType, i.RoleClaimType))
            .ToList();
        var granted = new ClaimsIdentity();
        foreach (var r in roles) granted.AddClaim(new Claim(ClaimTypes.Role, r));
        foreach (var p in permNames) granted.AddClaim(new Claim(AppClaimTypes.Permission, p));
        identities.Add(granted);
        return new ClaimsPrincipal(identities);
    }

    private IEnumerable<Claim> AppRoleClaims(ClaimsPrincipal p) => p.FindAll(ClaimTypes.Role).Where(IsAppRoleClaim);

    // A CaseBook role (built-in or custom) — as opposed to a Windows group SID carried as a role claim.
    private bool IsAppRoleClaim(Claim c) =>
        c.Type == ClaimTypes.Role && (Enum.TryParse<AppRole>(c.Value, out _) || Directory.IsRole(c.Value));
}
