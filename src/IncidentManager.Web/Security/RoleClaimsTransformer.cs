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

        var roleNames = _directory.RolesForGroups(GroupCandidates(principal));
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

    /// <summary>
    /// The AD group identifiers on a Windows principal to match against the group→role mappings. Windows groups arrive
    /// as Role/GroupSid claims whose VALUES are SIDs, but mappings are configured by NAME ("SOC-AppAdmins"), so this
    /// yields both the raw SID and its resolved name, with and without the DOMAIN\ prefix. Shared with the S-10
    /// session re-check so both resolve groups identically.
    /// </summary>
    public static IReadOnlySet<string> GroupCandidates(ClaimsPrincipal principal)
    {
        var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in principal.Claims)
        {
            if (c.Type != ClaimTypes.Role && c.Type != ClaimTypes.GroupSid) continue;
            candidates.Add(c.Value);
            foreach (var name in NamesForSid(c.Value)) candidates.Add(name);
        }
        return candidates;
    }

    /// <summary>The account name(s) for a group SID: "DOMAIN\Group" and the bare "Group". Empty for a
    /// value that isn't a SID (already a name) or that can't be resolved.</summary>
    internal static IEnumerable<string> NamesForSid(string value)
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
        // BUG-188: a group name is unique only within its domain, so the bare "Group" is offered only for a group of
        // this server's own domain (or the machine itself). A same-named group made in a trusted domain matches only a
        // mapping that names its domain.
        if (slash >= 0 && IsLocalToServer(value, resolved[..slash])) yield return resolved[(slash + 1)..];   // Group
    }

    // The domain this server is joined to, as the domain part of its computer account's SID; null when it can't be
    // found (not domain-joined, or not Windows), in which case there's no other domain to tell apart.
    private static readonly Lazy<string?> ServerDomainSid = new(() =>
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var sid = (SecurityIdentifier)new NTAccount(Environment.MachineName + "$").Translate(typeof(SecurityIdentifier));
            return sid.AccountDomainSid?.Value;
        }
        catch { return null; }   // not domain-joined, or AD unreachable
    });

    private static bool IsLocalToServer(string sid, string domain) =>
        !OperatingSystem.IsWindows() || IsLocalToServer(sid, domain, Environment.MachineName, ServerDomainSid.Value);

    /// <summary>Whether a group (its SID and the domain part of its name) belongs to the server: a local or built-in
    /// group, or one of the server's domain (<paramref name="serverDomainSid"/>; null when unknown, so any).</summary>
    public static bool IsLocalToServer(string sid, string domain, string machineName, string? serverDomainSid)
    {
        if (!OperatingSystem.IsWindows()) return true;
        if (string.Equals(domain, machineName, StringComparison.OrdinalIgnoreCase)) return true;   // a local group
        SecurityIdentifier? groupDomain;
        try { groupDomain = new SecurityIdentifier(sid).AccountDomainSid; }
        catch (ArgumentException) { return false; }
        if (groupDomain is null) return true;   // a built-in group (BUILTIN\…, NT AUTHORITY\…): this machine's
        return serverDomainSid is null || string.Equals(groupDomain.Value, serverDomainSid, StringComparison.OrdinalIgnoreCase);
    }
}
