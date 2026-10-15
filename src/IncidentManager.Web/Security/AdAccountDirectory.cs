using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Runtime.Versioning;
using IncidentManager.Application.Abstractions;

namespace IncidentManager.Web.Security;

/// <summary>
/// BUG-416: account lookups in Active Directory, as the app pool's identity (read-only; an authenticated account can
/// read these attributes). <c>DOMAIN\sam</c> is looked up in that domain, a bare name or a UPN in the server's own
/// domain. A lookup that takes longer than <see cref="Timeout"/> or fails is reported as unavailable, never as "not
/// found".
/// <para>
/// BUG-419: the value is an indicator from the case, so its domain may be an attacker's. Only the server's own forest and
/// the domains its domain has a trust with (<see cref="TrustedDomains"/>, read from our own domain controller) are
/// asked; any other <c>DOMAIN\</c>, and a local account (<c>.\sam</c>, <c>COMPUTER\sam</c>), answers NotLookedUp with no
/// network call. BUG-420: a domain that just failed answers Unavailable straight away for <see cref="BackOff"/>, and at
/// most <see cref="MaxInFlight"/> lookups (counting ones abandoned at the timeout) run at once, on their own threads.
/// BUG-471: that limit is per domain, and a domain with <see cref="MaxHungPerDomain"/> lookups that timed out and are
/// still blocked isn't asked again until one returns, so a hung domain controller holds a few threads, not every place.
/// </para>
/// </summary>
public sealed class AdAccountDirectory : IAccountDirectory
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    /// <summary>BUG-420: how long a domain that failed or timed out isn't asked again.</summary>
    public static readonly TimeSpan BackOff = TimeSpan.FromMinutes(1);

    /// <summary>BUG-420: lookups running at once in one domain (BUG-471), including ones still blocked after their caller
    /// stopped waiting.</summary>
    public const int MaxInFlight = 8;

    /// <summary>BUG-471: lookups in one domain that timed out and are still blocked, past which it isn't asked again.</summary>
    public const int MaxHungPerDomain = 2;

    // BUG-419: how long the list of trusted domains is kept (trusts change rarely); after a failure, retried sooner.
    private static readonly TimeSpan TrustedFor = TimeSpan.FromHours(1);

    private readonly ILogger<AdAccountDirectory>? _log;
    private readonly Func<string, DirectoryLookup> _query;
    private readonly Func<Action<Action>, IEnumerable<string>> _trustedDomains;
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTimeOffset> _failedUntil = new(StringComparer.OrdinalIgnoreCase);
    private (HashSet<string>? Names, DateTimeOffset Until)? _trusted;
    private Task<HashSet<string>?>? _listing;
    private int _listingGeneration;   // BUG-457: which listing is the current one
    private int _listingsRunning;     // BUG-471: including ones given up on that are still blocked
    // BUG-471: per domain, the lookups running, and those of them that timed out and are still blocked.
    private readonly Dictionary<string, int> _inFlight = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _hung = new(StringComparer.OrdinalIgnoreCase);

    /// <param name="query">The directory query for a name that may be asked (tests stand in for AD here).</param>
    /// <param name="trustedDomains">The NetBIOS and DNS names of the domains that may be asked. Each directory search is
    /// run through the action it's given, which judges whether that search ran into its time limit (BUG-498).</param>
    public AdAccountDirectory(ILogger<AdAccountDirectory>? log = null, Func<string, DirectoryLookup>? query = null,
        Func<Action<Action>, IEnumerable<string>>? trustedDomains = null, TimeProvider? time = null)
    {
        _log = log;
        _query = query ?? (OperatingSystem.IsWindows() ? Query : _ => DirectoryLookup.Unavailable("Active Directory lookups need Windows."));
        _trustedDomains = trustedDomains ?? (OperatingSystem.IsWindows() ? TrustedDomains : _ => []);
        _time = time ?? TimeProvider.System;
    }

    public bool IsAvailable => OperatingSystem.IsWindows();

    public async Task<DirectoryLookup> LookupAsync(string account, CancellationToken ct = default)
    {
        var name = (account ?? "").Trim();
        if (name.Length == 0) return DirectoryLookup.NotFound;
        var slash = name.IndexOf('\\');
        if (slash >= 0)
        {
            var domain = name[..slash];
            if (name.Length == slash + 1) return DirectoryLookup.NotFound;
            if (domain is "." || string.Equals(domain, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                return DirectoryLookup.NotLookedUp(
                    $"{domain}\\ is a local account on one computer, not a domain account, so it isn't looked up in the directory.");
            var trusted = await TrustedAsync(ct);
            if (trusted is null)
                return DirectoryLookup.Unavailable("CaseBook couldn't list the domains it may look accounts up in.");
            if (!trusted.Contains(domain.TrimEnd('.')))
                return DirectoryLookup.NotLookedUp(
                    $"{domain} isn't this server's domain or one it trusts, so the account wasn't looked up.");
        }
        return await QueryAsync(name, slash > 0 ? name[..slash].TrimEnd('.') : "", ct);
    }

    // BUG-420: one query on its own thread (a blocked LDAP call doesn't hold a pool thread), at most MaxInFlight at once
    // in a domain, and a domain that just failed isn't asked again until BackOff has passed.
    private async Task<DirectoryLookup> QueryAsync(string name, string domainKey, CancellationToken ct)
    {
        var slot = new Slot();
        lock (_gate)
        {
            if (_failedUntil.TryGetValue(domainKey, out var until) && until > _time.GetUtcNow())
                return DirectoryLookup.Unavailable("Active Directory didn't answer a moment ago; try again in a minute.");
            // BUG-471: a domain whose earlier lookups timed out and are still blocked isn't given another thread.
            if (_hung.GetValueOrDefault(domainKey) >= MaxHungPerDomain)
                return DirectoryLookup.Unavailable("Active Directory hasn't answered earlier lookups in this domain yet; try again later.");
            if (_inFlight.GetValueOrDefault(domainKey) >= MaxInFlight)
                return DirectoryLookup.Unavailable("Active Directory is still answering earlier lookups; try again shortly.");
            Count(_inFlight, domainKey, +1);
        }
        var query = Task.Factory.StartNew(() =>
        {
            try { return _query(name); }
            finally
            {
                lock (_gate)
                {
                    slot.Done = true;
                    Count(_inFlight, domainKey, -1);
                    if (slot.Hung) Count(_hung, domainKey, -1);
                }
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        DirectoryLookup result;
        var domainFailed = false;   // only the directory not answering backs the domain off, not one name's own trouble
        try
        {
            result = await query.WaitAsync(Timeout, _time, ct);
        }
        catch (TimeoutException)
        {
            result = DirectoryLookup.Unavailable("Active Directory didn't answer in time.");
            domainFailed = true;
            lock (_gate)
            {
                if (!slot.Done) { slot.Hung = true; Count(_hung, domainKey, +1); }
            }
        }
        catch (MultipleMatchesException)
        {
            // An indicator's text (or a partial name typed) matching more than one account says nothing about the domain,
            // so it's this name not being looked up (capture carries on with the rest), not the directory being down.
            result = DirectoryLookup.NotLookedUp("More than one directory account matches this name.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.LogWarning(ex, "Couldn't look an account up in Active Directory.");
            result = DirectoryLookup.Unavailable("Active Directory couldn't be reached.");
            domainFailed = true;
        }
        lock (_gate)
        {
            if (domainFailed) _failedUntil[domainKey] = _time.GetUtcNow() + BackOff;
            else if (result.Outcome != DirectoryLookupOutcome.Unavailable) _failedUntil.Remove(domainKey);
        }
        return result;
    }

    private sealed class Slot
    {
        public bool Done;
        public bool Hung;   // timed out, still blocked
    }

    // Called under _gate; a domain with nothing left isn't kept.
    private static void Count(Dictionary<string, int> counts, string key, int by)
    {
        var n = counts.GetValueOrDefault(key) + by;
        if (n > 0) counts[key] = n;
        else counts.Remove(key);
    }

    // BUG-419: the domains that may be asked, listed once and kept; null when they couldn't be listed (then retried
    // after BackOff). One listing runs at a time, on its own thread, bounded by Timeout.
    private async Task<HashSet<string>?> TrustedAsync(CancellationToken ct)
    {
        Task<HashSet<string>?> listing;
        lock (_gate)
        {
            if (_trusted is { } t && t.Until > _time.GetUtcNow()) return t.Names;
            if (_listing is null)
            {
                // BUG-471: while listings given up on are still blocked (as many as a domain's lookups may be), another
                // isn't started on top of them.
                if (_listingsRunning >= MaxHungPerDomain)
                {
                    _trusted = (null, _time.GetUtcNow() + BackOff);
                    return null;
                }
                _listingsRunning++;
                var generation = ++_listingGeneration;
                _listing = Task.Factory.StartNew(() => ListTrusted(generation), CancellationToken.None,
                    TaskCreationOptions.LongRunning, TaskScheduler.Default);
            }
            listing = _listing;
        }
        try { return await listing.WaitAsync(Timeout, _time, ct); }
        catch (TimeoutException)
        {
            // BUG-457: a listing that hangs is given up on, as a failure, so the next lookup after BackOff starts a new one
            // rather than waiting on this one for good.
            lock (_gate)
            {
                if (ReferenceEquals(_listing, listing))
                {
                    _listing = null;
                    _trusted = (null, _time.GetUtcNow() + BackOff);
                }
            }
            return null;
        }
    }

    private HashSet<string>? ListTrusted(int generation)
    {
        HashSet<string>? names = null;
        try
        {
            names = new HashSet<string>(_trustedDomains(Searched).Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim().TrimEnd('.')),
                StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            _log?.LogWarning(ex, "Couldn't list the domains this server trusts; accounts in a named domain aren't looked up.");
        }
        lock (_gate)
        {
            _listingsRunning--;
            // BUG-457/498: one given up on that a newer one has started after records nothing. With none newer, its late
            // answer is kept, so a slow but complete list isn't lost.
            var current = generation == _listingGeneration;
            if (current)
            {
                _trusted = (names, _time.GetUtcNow() + (names is null ? BackOff : TrustedFor));
                _listing = null;
            }
        }
        return names;
    }

    // The forest's domains (each domain's crossRef in the configuration partition) and the domains our domain has a
    // trust with (its trustedDomain objects), as NetBIOS and DNS names. Read from our own domain controller.
    [SupportedOSPlatform("windows")]
    private static IEnumerable<string> TrustedDomains(Action<Action> searched)
    {
        var names = new List<string>();
        using var rootDse = new DirectoryEntry("LDAP://RootDSE");
        var config = rootDse.Properties["configurationNamingContext"].Value as string;
        var domainNc = rootDse.Properties["defaultNamingContext"].Value as string;
        // systemFlags bit 2 (FLAG_CR_NTDS_DOMAIN): the crossRef of an AD domain.
        var domainNcs = Read($"LDAP://CN=Partitions,{config}", "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))",
            ["nETBIOSName", "dnsRoot"], names, searched, check: "nCName");
        // BUG-470: the forest's list always has our own domain; one without it was cut short.
        if (domainNc is null || !domainNcs.Contains(domainNc))
            throw new InvalidOperationException("The forest's list of domains came back without this server's own domain.");
        Read($"LDAP://CN=System,{domainNc}", "(objectClass=trustedDomain)", ["flatName", "trustPartner"], names, searched);
        return names;
    }

    // BUG-457/470: how long one search may take. Only the client's limit is set (a server time limit ends a search the
    // same silent way), and Searched takes a search that ran this long to be incomplete.
    private static readonly TimeSpan SearchLimit = Timeout;

    // BUG-470: a search that reaches its time limit ends with what it had so far and no error, so one that ran that long
    // may be missing domains: the listing fails (retried after BackOff) rather than being kept for an hour. BUG-498: each
    // search is judged on its own; the RootDSE bind and the other search don't count towards its limit.
    private void Searched(Action search)
    {
        var started = _time.GetTimestamp();
        search();
        if (_time.GetElapsedTime(started) >= SearchLimit - TimeSpan.FromSeconds(1))
            throw new TimeoutException("A search for the domains this server trusts ran into its time limit, so it may be incomplete.");
    }

    // Adds the attributes' values to into, and returns the values of check, which tell whether the search was complete.
    [SupportedOSPlatform("windows")]
    private static HashSet<string> Read(string path, string filter, string[] attributes, List<string> into,
        Action<Action> searched, string? check = null)
    {
        using var root = new DirectoryEntry(path);
        // BUG-498: bound before the search is timed, so a slow bind isn't taken for a search cut short.
        _ = root.NativeObject;
        // BUG-457: bounded, so a domain controller that hangs ends the listing instead of holding its thread for good.
        using var searcher = new DirectorySearcher(root, filter, check is null ? attributes : [.. attributes, check], SearchScope.OneLevel)
        {
            ClientTimeout = SearchLimit,
        };
        var checks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // The results arrive as they're read, so reading them is part of the search's time.
        searched(() =>
        {
            using var results = searcher.FindAll();
            foreach (SearchResult r in results)
            {
                foreach (var a in attributes)
                    if (r.Properties.Contains(a))
                        foreach (var v in r.Properties[a])
                            if (v?.ToString() is { Length: > 0 } s) into.Add(s);
                if (check is not null && r.Properties.Contains(check))
                    foreach (var v in r.Properties[check])
                        if (v?.ToString() is { Length: > 0 } s) checks.Add(s);
            }
        });
        return checks;
    }

    // Only called for a name LookupAsync allows: a bare name or a UPN (the server's own domain), or DOMAIN\sam in a
    // domain the server trusts.
    [SupportedOSPlatform("windows")]
    private static DirectoryLookup Query(string name)
    {
        var slash = name.IndexOf('\\');
        var domain = slash > 0 ? name[..slash] : null;
        var identity = slash >= 0 ? name[(slash + 1)..] : name;

        using var ctx = domain is not null ? new PrincipalContext(ContextType.Domain, domain) : new PrincipalContext(ContextType.Domain);
        using var user = UserPrincipal.FindByIdentity(ctx, identity);
        if (user is null) return DirectoryLookup.NotFound;

        string? title = null, department = null, manager = null;
        DateTimeOffset? created = null;
        if (user.GetUnderlyingObject() is DirectoryEntry entry)
        {
            title = Attr(entry, "title");
            department = Attr(entry, "department");
            manager = ManagerName(Attr(entry, "manager"));
            if (entry.Properties["whenCreated"]?.Value is DateTime when) created = Utc(when);
        }

        bool? locked;
        try { locked = user.IsAccountLockedOut(); } catch (PrincipalOperationException) { locked = null; }

        return DirectoryLookup.Of(new DirectoryAccount(
            user.SamAccountName ?? identity, domain, user.UserPrincipalName, user.DisplayName,
            title, department, manager, user.EmailAddress, user.DistinguishedName, user.Enabled, locked,
            user.AccountExpirationDate is { } exp ? Utc(exp) : null,
            user.LastLogon is { } logon ? Utc(logon) : null,
            user.LastPasswordSet is { } pwd ? Utc(pwd) : null,
            created));
    }

    [SupportedOSPlatform("windows")]
    private static string? Attr(DirectoryEntry entry, string name) =>
        entry.Properties.Contains(name) && entry.Properties[name].Value is { } v ? v.ToString() : null;

    // "CN=Rivera\, Jordan,OU=Staff,DC=corp,DC=example" → "Rivera, Jordan". The manager's own entry isn't read.
    internal static string? ManagerName(string? dn)
    {
        if (string.IsNullOrWhiteSpace(dn) || !dn.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)) return dn;
        var sb = new System.Text.StringBuilder();
        for (var i = 3; i < dn.Length; i++)
        {
            if (dn[i] == '\\' && i + 1 < dn.Length) { sb.Append(dn[++i]); continue; }
            if (dn[i] == ',') break;
            sb.Append(dn[i]);
        }
        return sb.ToString();
    }

    private static DateTimeOffset Utc(DateTime t) =>
        new(t.Kind == DateTimeKind.Local ? t.ToUniversalTime() : DateTime.SpecifyKind(t, DateTimeKind.Utc), TimeSpan.Zero);
}

/// <summary>BUG-416: where there's no directory (sign-in that isn't Windows, outside development).</summary>
public sealed class NoAccountDirectory : IAccountDirectory
{
    public bool IsAvailable => false;
    public Task<DirectoryLookup> LookupAsync(string account, CancellationToken ct = default) =>
        Task.FromResult(DirectoryLookup.Unavailable("There's no directory to look accounts up in here."));
}

/// <summary>
/// BUG-416: development only, so the lookup can be tried without a domain. Knows a few made-up CONTOSO accounts (any
/// domain prefix, or none); everything else is not found.
/// </summary>
public sealed class DevAccountDirectory : IAccountDirectory
{
    private static readonly DateTimeOffset Base = new(2026, 9, 1, 13, 0, 0, TimeSpan.Zero);

    private static readonly Dictionary<string, DirectoryAccount> Known = new(StringComparer.OrdinalIgnoreCase)
    {
        ["jdoe"] = new("jdoe", "CONTOSO", "jdoe@contoso.example", "Jordan Doe", "Claims Analyst", "Finance", "Rivera, Sam",
            "jordan.doe@contoso.example", "CN=Jordan Doe,OU=Staff,DC=contoso,DC=example", true, false, null,
            Base.AddDays(42), Base.AddDays(-30), Base.AddYears(-3)),
        ["svc_backup"] = new("svc_backup", "CONTOSO", null, "Backup service", null, "IT Operations", null, null,
            "CN=svc_backup,OU=Service Accounts,DC=contoso,DC=example", true, false, null, Base.AddDays(43), Base.AddYears(-2),
            Base.AddYears(-4)),
        ["asmith"] = new("asmith", "CONTOSO", "asmith@contoso.example", "Alex Smith", "Contractor", "Facilities", "Doe, Jordan",
            "alex.smith@contoso.example", "CN=Alex Smith,OU=Contractors,DC=contoso,DC=example", false, true, Base.AddDays(-5),
            Base.AddDays(-20), Base.AddDays(-90), Base.AddMonths(-8)),
    };

    public bool IsAvailable => true;

    public Task<DirectoryLookup> LookupAsync(string account, CancellationToken ct = default)
    {
        var name = (account ?? "").Trim();
        var at = name.IndexOf('@');
        var sam = name.Contains('\\') ? name[(name.IndexOf('\\') + 1)..] : at > 0 ? name[..at] : name;
        return Task.FromResult(Known.TryGetValue(sam, out var a) ? DirectoryLookup.Of(a) : DirectoryLookup.NotFound);
    }
}
