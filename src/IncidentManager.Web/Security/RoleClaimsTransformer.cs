using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Principal;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using Microsoft.AspNetCore.Authentication;

namespace IncidentManager.Web.Security;

/// <summary>
/// For Windows-authenticated users, translates AD group membership into role and permission claims
/// using the database-backed <see cref="IRoleDirectory"/>. Applied only in Windows auth mode.
/// </summary>
public sealed class RoleClaimsTransformer : IClaimsTransformation
{
    // SID -> account name (e.g. "AD\SOC-AppAdmins"). Stable for the process lifetime; caching avoids an
    // AD/LSA lookup per request. A group rename is picked up on the next app restart.
    private static readonly ConcurrentDictionary<string, string?> SidNameCache = new(StringComparer.OrdinalIgnoreCase);

    private readonly IRoleDirectory _directory;

    public RoleClaimsTransformer(IRoleDirectory directory) => _directory = directory;

    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated != true)
            return Task.FromResult(principal);

        // Windows groups arrive as Role/GroupSid claims whose VALUES are SIDs, but the AD-group->role
        // mapping is configured by NAME ("SOC-AppAdmins"). Match on both: the raw SID and the SID's
        // resolved name, with and without the DOMAIN\ prefix, so name-based config resolves.
        var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in principal.Claims)
        {
            if (c.Type != ClaimTypes.Role && c.Type != ClaimTypes.GroupSid) continue;
            candidates.Add(c.Value);
            foreach (var name in NamesForSid(c.Value)) candidates.Add(name);
        }

        var roleNames = _directory.RolesForGroups(candidates);
        if (roleNames.Count == 0)
            return Task.FromResult(principal);

        var identity = new ClaimsIdentity();
        foreach (var role in roleNames)
        {
            if (!principal.IsInRole(role))
                identity.AddClaim(new Claim(ClaimTypes.Role, role));
        }

        // Permission claims are what policies authorize on.
        foreach (var perm in _directory.PermissionsForRoles(roleNames))
        {
            if (!principal.HasClaim(AppClaimTypes.Permission, perm.ToString()))
                identity.AddClaim(new Claim(AppClaimTypes.Permission, perm.ToString()));
        }

        principal.AddIdentity(identity);
        return Task.FromResult(principal);
    }

    /// <summary>The account name(s) for a group SID: "DOMAIN\Group" and the bare "Group". Empty for a
    /// value that isn't a SID (already a name) or that can't be resolved.</summary>
    private static IEnumerable<string> NamesForSid(string value)
    {
        if (!value.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
            yield break;

        var resolved = SidNameCache.GetOrAdd(value, static sid =>
        {
            if (!OperatingSystem.IsWindows()) return null;
            try { return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value; }
            catch { return null; } // well-known/orphaned SID, or AD unreachable
        });
        if (resolved is null) yield break;

        yield return resolved;                                  // DOMAIN\Group
        var slash = resolved.IndexOf('\\');
        if (slash >= 0) yield return resolved[(slash + 1)..];   // Group
    }
}
