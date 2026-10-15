using System.Collections.Concurrent;
using System.DirectoryServices.AccountManagement;
using System.Runtime.Versioning;

namespace IncidentManager.Web.Security;

/// <summary>
/// Turns a Windows account name (<c>DOMAIN\sam</c>) into the person's real display name. Windows
/// authentication only gives us <c>DOMAIN\sam</c>; this looks up the AD display name (e.g. "Jordan
/// Rivera") so the UI never shows the domain or the bare logon name. A name found is cached for the process lifetime;
/// every failure path degrades gracefully to the bare username (never the domain), and is tried again after
/// <see cref="RetryUnresolved"/> (REV-67), so one domain-controller blip doesn't fix "jdoe" as someone's name until the
/// app pool recycles (written into the user mirror and into hashed records such as assignments).
/// <para>
/// BUG-565: it runs on every authenticated request, so the lookup is bounded (<see cref="BoundedDirectoryCalls{T}"/>): one
/// per name at a time, waited on for <see cref="Timeout"/>, after which the bare username is used (not kept, so it's
/// looked up again) and a name that lands later is kept. A domain with <see cref="MaxHung"/> lookups still blocked isn't
/// asked again until one returns, so a hung domain controller holds a few threads, not one per request.
/// </para>
/// </summary>
public sealed class WindowsNames
{
    public static readonly TimeSpan RetryUnresolved = TimeSpan.FromMinutes(5);

    /// <summary>BUG-565: how long a request waits for a display name before showing the bare username. Short: only a
    /// name is at stake, and it's put right once the lookup lands.</summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);

    /// <summary>BUG-565: lookups running at once in one domain, including ones still blocked after their callers gave up.</summary>
    public const int MaxInFlight = 8;

    /// <summary>BUG-565: lookups in one domain still blocked after timing out, past which it isn't asked again.</summary>
    public const int MaxHung = 2;

    private static readonly WindowsNames Shared = new();

    private readonly ConcurrentDictionary<string, (string? Name, DateTimeOffset RetryAfterUtc)> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly BoundedDirectoryCalls<string?> _calls;
    private readonly TimeSpan _timeout;
    private readonly TimeProvider _time;

    /// <param name="query">The display name for a <c>DOMAIN\sam</c>, or null (tests stand in for AD here).</param>
    public WindowsNames(Func<string, string?>? query = null, TimeSpan? timeout = null, TimeProvider? time = null)
    {
        var lookup = query ?? ResolveDisplayName;
        _timeout = timeout ?? Timeout;
        _time = time ?? TimeProvider.System;
        _calls = new BoundedDirectoryCalls<string?>(
            names => names.ToDictionary(n => n, n => Safe(lookup, n), StringComparer.OrdinalIgnoreCase),
            Landed, DomainOf, MaxInFlight, MaxHung);
    }

    /// <summary>
    /// A human-friendly name for an identity: the AD display name for a <c>DOMAIN\sam</c> account, the
    /// bare sAMAccountName if AD can't be reached (or doesn't answer in time), or the value unchanged when it isn't a
    /// domain account (e.g. the dev "Dev Analyst", or a UPN). Null in, null out.
    /// </summary>
    public static string? Friendly(string? identityName) => Shared.Resolve(identityName);

    /// <summary>As <see cref="Friendly"/>, without holding the caller's thread while AD is asked.</summary>
    public static Task<string?> FriendlyAsync(string? identityName) => Shared.ResolveAsync(identityName);

    public string? Resolve(string? identityName)
    {
        if (Known(identityName, out var known)) return known;
        _calls.Wait([identityName!], _timeout);
        return Kept(identityName!);
    }

    public async Task<string?> ResolveAsync(string? identityName)
    {
        if (Known(identityName, out var known)) return known;
        await _calls.WaitAsync([identityName!], _timeout);
        return Kept(identityName!);
    }

    // The answer without asking AD: for a name that isn't DOMAIN\sam, one kept, or one that failed a moment ago.
    private bool Known(string? identityName, out string? name)
    {
        name = identityName;
        if (string.IsNullOrWhiteSpace(identityName)) return true;
        var slash = identityName.IndexOf('\\');
        if (slash < 0) return true;                         // not DOMAIN\sam (dev auth, UPN, plain name)
        name = identityName[(slash + 1)..];
        if (name.Length == 0) return true;                  // no sam to look up
        if (_cache.TryGetValue(identityName, out var cached) && (cached.Name is not null || _time.GetUtcNow() < cached.RetryAfterUtc))
        {
            name = cached.Name ?? name;
            return true;
        }
        return false;
    }

    // BUG-565: what's kept once the wait ends; the bare username when the lookup hasn't landed (or found nothing).
    private string Kept(string identityName) =>
        _cache.TryGetValue(identityName, out var cached) && cached.Name is not null
            ? cached.Name
            : identityName[(identityName.IndexOf('\\') + 1)..];

    private void Landed(IReadOnlyList<string> names, IReadOnlyDictionary<string, string?> found)
    {
        var retry = _time.GetUtcNow() + RetryUnresolved;
        foreach (var n in names)
            _cache[n] = found.GetValueOrDefault(n) is { } name ? (name, DateTimeOffset.MaxValue) : (null, retry);
    }

    private static string DomainOf(string domainAndSam) => domainAndSam[..domainAndSam.IndexOf('\\')];

    private static string? Safe(Func<string, string?> lookup, string domainAndSam)
    {
        try { return lookup(domainAndSam) is { } n && !string.IsNullOrWhiteSpace(n) ? n.Trim() : null; }
        catch { return null; }   // degrade to the bare username, tried again after RetryUnresolved
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
            var domain = domainAndSam[..slash];
            var sam = domainAndSam[(slash + 1)..];

            // BUG-400: the account's own domain, not the server's. A trusted-domain user's sam looked up in the server's
            // domain found a namesake there, whose name was shown and stored. A local account (the server's own name)
            // is looked up on the machine. An authenticated account can read display-name attributes. Kept
            // short-lived; the result is cached by the caller.
            using var ctx = string.Equals(domain, Environment.MachineName, StringComparison.OrdinalIgnoreCase)
                ? new PrincipalContext(ContextType.Machine)
                : new PrincipalContext(ContextType.Domain, domain.Length == 0 ? null : domain);
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
