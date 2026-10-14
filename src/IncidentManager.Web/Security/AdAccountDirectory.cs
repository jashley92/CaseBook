using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Runtime.Versioning;
using IncidentManager.Application.Abstractions;

namespace IncidentManager.Web.Security;

/// <summary>
/// BUG-416: account lookups in Active Directory, as the app pool's identity (read-only; an authenticated account can
/// read these attributes). <c>DOMAIN\sam</c> is looked up in that domain (as <see cref="WindowsNames"/> does, BUG-400),
/// <c>.\sam</c> on this machine, a bare name or a UPN in the server's own domain. A lookup that takes longer than
/// <see cref="Timeout"/> or fails is reported as unavailable, never as "not found".
/// </summary>
public sealed class AdAccountDirectory : IAccountDirectory
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private readonly ILogger<AdAccountDirectory>? _log;
    private readonly Func<string, DirectoryLookup> _query;

    public AdAccountDirectory(ILogger<AdAccountDirectory>? log = null, Func<string, DirectoryLookup>? query = null)
    {
        _log = log;
        _query = query ?? (OperatingSystem.IsWindows() ? Query : _ => DirectoryLookup.Unavailable("Active Directory lookups need Windows."));
    }

    public bool IsAvailable => OperatingSystem.IsWindows();

    public async Task<DirectoryLookup> LookupAsync(string account, CancellationToken ct = default)
    {
        var name = (account ?? "").Trim();
        if (name.Length == 0) return DirectoryLookup.NotFound;
        try
        {
            return await Task.Run(() => _query(name), ct).WaitAsync(Timeout, ct);
        }
        catch (TimeoutException)
        {
            return DirectoryLookup.Unavailable("Active Directory didn't answer in time.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.LogWarning(ex, "Couldn't look an account up in Active Directory.");
            return DirectoryLookup.Unavailable("Active Directory couldn't be reached.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static DirectoryLookup Query(string name)
    {
        var slash = name.IndexOf('\\');
        var domain = slash > 0 ? name[..slash] : null;
        var identity = slash >= 0 ? name[(slash + 1)..] : name;
        var local = slash == 1 && name[0] == '.'
                    || (domain is not null && string.Equals(domain, Environment.MachineName, StringComparison.OrdinalIgnoreCase));

        using var ctx = local ? new PrincipalContext(ContextType.Machine)
            : domain is not null ? new PrincipalContext(ContextType.Domain, domain)
            : new PrincipalContext(ContextType.Domain);
        using var user = UserPrincipal.FindByIdentity(ctx, identity);
        if (user is null) return DirectoryLookup.NotFound;

        string? title = null, department = null, manager = null;
        DateTimeOffset? created = null;
        if (!local && user.GetUnderlyingObject() is DirectoryEntry entry)
        {
            title = Attr(entry, "title");
            department = Attr(entry, "department");
            manager = ManagerName(Attr(entry, "manager"));
            if (entry.Properties["whenCreated"]?.Value is DateTime when) created = Utc(when);
        }

        bool? locked;
        try { locked = user.IsAccountLockedOut(); } catch (PrincipalOperationException) { locked = null; }

        return DirectoryLookup.Of(new DirectoryAccount(
            user.SamAccountName ?? identity, local ? Environment.MachineName : domain, user.UserPrincipalName, user.DisplayName,
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
