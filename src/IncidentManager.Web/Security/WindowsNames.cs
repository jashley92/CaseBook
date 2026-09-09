using System.Collections.Concurrent;
using System.DirectoryServices.AccountManagement;
using System.Runtime.Versioning;

namespace IncidentManager.Web.Security;

/// <summary>
/// Turns a Windows account name (<c>DOMAIN\sam</c>) into the person's real display name. Windows
/// authentication only gives us <c>DOMAIN\sam</c>; this looks up the AD display name (e.g. "Jordan
/// Rivera") so the UI never shows the domain or the bare logon name. Results are cached for the
/// process lifetime, and every failure path degrades gracefully to the bare username — never the domain.
/// </summary>
internal static class WindowsNames
{
    private static readonly ConcurrentDictionary<string, string> Cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// A human-friendly name for an identity: the AD display name for a <c>DOMAIN\sam</c> account, the
    /// bare sAMAccountName if AD can't be reached, or the value unchanged when it isn't a domain account
    /// (e.g. the dev "Dev Analyst", or a UPN). Null in, null out.
    /// </summary>
    public static string? Friendly(string? identityName)
    {
        if (string.IsNullOrWhiteSpace(identityName)) return identityName;

        var slash = identityName.IndexOf('\\');
        if (slash < 0) return identityName;                 // not DOMAIN\sam (dev auth, UPN, plain name)

        var sam = identityName[(slash + 1)..];
        return Cache.GetOrAdd(identityName, key => ResolveDisplayName(key) ?? sam);
    }

    private static string? ResolveDisplayName(string domainAndSam)
    {
        if (!OperatingSystem.IsWindows()) return null;
        return ResolveOnWindows(domainAndSam);
    }

    [SupportedOSPlatform("windows")]
    private static string? ResolveOnWindows(string domainAndSam)
    {
        try
        {
            var slash = domainAndSam.IndexOf('\\');
            var sam = domainAndSam[(slash + 1)..];

            // Current domain (the app-pool identity is domain-joined); an authenticated account can read
            // display-name attributes. Kept short-lived; the result is cached by the caller.
            using var ctx = new PrincipalContext(ContextType.Domain);
            using var user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, sam);
            if (user is null) return null;

            var name = user.DisplayName;
            if (string.IsNullOrWhiteSpace(name))
                name = string.Join(' ',
                    new[] { user.GivenName, user.Surname }.Where(s => !string.IsNullOrWhiteSpace(s)));

            return string.IsNullOrWhiteSpace(name) ? null : name.Trim();
        }
        catch
        {
            // AD unreachable, insufficient rights, or a non-domain account — degrade to the bare username.
            return null;
        }
    }
}
