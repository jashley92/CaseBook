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
    // AD/LSA lookup per request. A group rename is picked up on the next app restart. BUG-223: a lookup that found no
    // name (an AD blip as much as an orphaned SID) is kept only for RetryUnresolved, so a group whose first lookup hit
    // a DC failover doesn't lose its name-mapped roles for everyone until the app pool recycles.
    private static readonly ConcurrentDictionary<string, (string? Name, DateTime RetryAfterUtc)> SidNameCache =
        new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan RetryUnresolved = TimeSpan.FromMinutes(5);

    private static ILogger? _log;   // the first instance's; the lookups below are static (shared with the S-10 re-check)
    private readonly IRoleDirectory _directory;

    public RoleClaimsTransformer(IRoleDirectory directory, ILogger<RoleClaimsTransformer>? log = null)
    {
        _directory = directory;
        _log ??= log;
    }

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
        // WF-42: only the signed-in identity's claims. The roles CaseBook grants ride on an unauthenticated identity it
        // adds (here and in the S-10 re-check); read as groups, a role named like an AD group picked up that group's
        // mappings, and a removed mapping never took the role away.
        foreach (var c in principal.Identities.Where(i => i.IsAuthenticated).SelectMany(i => i.Claims))
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

        var now = DateTime.UtcNow;
        if (!SidNameCache.TryGetValue(value, out var cached) || (cached.Name is null && now >= cached.RetryAfterUtc))
        {
            string? name = null;
            if (OperatingSystem.IsWindows())
            {
                try { name = new SecurityIdentifier(value).Translate(typeof(NTAccount)).Value; }
                catch { /* well-known/orphaned SID, or AD unreachable: tried again after RetryUnresolved */ }
            }
            cached = (name, now + RetryUnresolved);
            SidNameCache[value] = cached;
        }
        var resolved = cached.Name;
        if (resolved is null) yield break;

        yield return resolved;                                  // DOMAIN\Group
        var slash = resolved.IndexOf('\\');
        // BUG-188: a group name is unique only within its domain, so the bare "Group" is offered only for a group of
        // this server's own domain (or the machine itself). A same-named group made in a trusted domain matches only a
        // mapping that names its domain.
        if (slash >= 0 && IsLocalToServer(value, resolved[..slash])) yield return resolved[(slash + 1)..];   // Group
    }

    // The domain this server is joined to, as the domain part of its computer account's SID. BUG-223: only a found one
    // is kept. A failed lookup was cached for the life of the process as "no domain", which offers bare names for every
    // domain's groups: one DC failover at app-pool start undid BUG-188 until the next recycle, with nothing logged.
    private static string? _serverDomainSid;
    private static DateTime _serverDomainRetryUtc;
    private static bool _serverDomainWarned;
    private static readonly object ServerDomainLock = new();
    private static readonly TimeSpan RetryServerDomain = TimeSpan.FromMinutes(1);

    // Null when the server isn't domain-joined (no other domain to tell apart); "" when it is but its domain couldn't
    // be found, which matches no domain, so only names that carry their domain map until it's found (fail closed).
    private static string? ServerDomainSid()
    {
        if (_serverDomainSid is { } known) return known;
        if (!OperatingSystem.IsWindows()) return null;
        lock (ServerDomainLock)
        {
            if (_serverDomainSid is { } again) return again;
            if (!IsDomainJoined()) return null;
            if (DateTime.UtcNow < _serverDomainRetryUtc) return "";
            try
            {
                var sid = (SecurityIdentifier)new NTAccount(Environment.MachineName + "$").Translate(typeof(SecurityIdentifier));
                if (sid.AccountDomainSid?.Value is { } found)
                {
                    if (_serverDomainWarned) _log?.LogWarning("Found this server's domain: bare AD group names map again.");
                    _serverDomainWarned = false;
                    return _serverDomainSid = found;
                }
            }
            catch (Exception ex)
            {
                if (!_serverDomainWarned)
                    _log?.LogCritical(ex, "Couldn't look up this server's AD domain (a DC unreachable?). Until it's found, " +
                        "only role mappings that name the domain (DOMAIN\\Group) take effect. Retrying every {Seconds} s.",
                        RetryServerDomain.TotalSeconds);
                _serverDomainWarned = true;
            }
            _serverDomainRetryUtc = DateTime.UtcNow + RetryServerDomain;
            return "";
        }
    }

    private static bool IsDomainJoined()
    {
        try { return !string.IsNullOrEmpty(System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName); }
        catch { return true; }   // can't tell: assume joined, so a failed lookup fails closed
    }

    private static bool IsLocalToServer(string sid, string domain) =>
        !OperatingSystem.IsWindows() || IsLocalToServer(sid, domain, Environment.MachineName, ServerDomainSid());

    /// <summary>Whether a group (its SID and the domain part of its name) belongs to the server: a local or built-in
    /// group, or one of the server's domain (<paramref name="serverDomainSid"/>; null when the server isn't on a domain,
    /// so any; "" when it is but the domain isn't known yet, so none).</summary>
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
