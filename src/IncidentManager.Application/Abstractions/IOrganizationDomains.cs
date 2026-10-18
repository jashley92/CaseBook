using System.Globalization;

namespace IncidentManager.Application.Abstractions;

/// <summary>CAP-28 discovery: where a domain found on the server's network came from.</summary>
public enum DiscoveredDomainSource
{
    /// <summary>The Active Directory domain the server is joined to.</summary>
    ThisDomain,
    /// <summary>The root domain of the server's forest (its parent).</summary>
    ForestRoot,
    /// <summary>Another domain in the server's forest.</summary>
    Forest,
    /// <summary>A domain the server's domain or forest has a trust with.</summary>
    Trusted,
}

/// <summary>CAP-28 discovery: one domain found on the server's network, and where from.</summary>
public sealed record DiscoveredDomain(string Name, DiscoveredDomainSource Source)
{
    /// <summary>The source in words, for "corp.contoso.com (this domain)".</summary>
    public string SourceLabel => Source switch
    {
        DiscoveredDomainSource.ThisDomain => "this domain",
        DiscoveredDomainSource.ForestRoot => "forest root",
        DiscoveredDomainSource.Forest => "same forest",
        _ => "trusted",
    };
}

/// <summary>CAP-28 discovery: how the last look at the server's network ended.</summary>
public enum DomainDiscoveryState
{
    /// <summary>Not looked yet (it runs in the background after start-up).</summary>
    NotYet,
    /// <summary>Read from Active Directory; <see cref="DomainDiscovery.Domains"/> may still be empty.</summary>
    Found,
    /// <summary>The server isn't joined to an Active Directory domain, or isn't Windows.</summary>
    NotDomainJoined,
    /// <summary>Active Directory didn't answer within the time limit.</summary>
    TimedOut,
    /// <summary>Reading Active Directory failed.</summary>
    Failed,
}

/// <summary>
/// CAP-28 discovery: what was found on the server's network, normalized as a saved domain would be (a NetBIOS name, a
/// single label, is refused and counted in <see cref="Refused"/>) and without duplicates, or why nothing was.
/// </summary>
/// <param name="ErrorType">For <see cref="DomainDiscoveryState.Failed"/>, the exception's type name only (its message can
/// carry a server's name or a path).</param>
public sealed record DomainDiscovery(DomainDiscoveryState State, IReadOnlyList<DiscoveredDomain> Domains,
    DateTimeOffset? AtUtc = null, string? ErrorType = null, int Refused = 0)
{
    public static readonly DomainDiscovery NotYet = new(DomainDiscoveryState.NotYet, []);

    /// <summary>The names, one per line as the setting is saved, or null when nothing was found.</summary>
    public string? NamesText => Domains.Count == 0 ? null : string.Join("\n", Domains.Select(d => d.Name));

    /// <summary>"corp.contoso.com (this domain), contoso.com (forest root)".</summary>
    public string Described => string.Join(", ", Domains.Select(d => $"{d.Name} ({d.SourceLabel})"));

    /// <summary>What happened, in words, for Diagnostics.</summary>
    public string Summary(TimeSpan timeLimit) => State switch
    {
        DomainDiscoveryState.NotYet => "Not looked yet: it runs in the background shortly after start-up.",
        DomainDiscoveryState.Found when Domains.Count > 0 => $"Found {Described}.",
        DomainDiscoveryState.Found => "This server is on a domain, but none of the names found is a full domain name.",
        DomainDiscoveryState.NotDomainJoined => "This server isn't joined to an Active Directory domain.",
        DomainDiscoveryState.TimedOut => $"Active Directory didn't answer within {timeLimit.TotalSeconds.ToString("0", CultureInfo.InvariantCulture)} seconds.",
        _ => $"Active Directory couldn't be read ({ErrorType ?? "error"}).",
    };
}

/// <summary>
/// CAP-28 discovery: the organization's domains as found on the server's network (the AD domain it's joined to, its
/// forest root, the forest's other domains and the trusted ones), offered as the default for "Your organization's
/// domains" while no administrator has set it. Looked up once in the background after start-up, bounded in time, and
/// kept for the app's lifetime; an administrator can look again.
/// </summary>
public interface IOrganizationDomains
{
    /// <summary>The last look's result (never blocks; <see cref="DomainDiscovery.NotYet"/> before the first).</summary>
    DomainDiscovery Current { get; }

    /// <summary>The time limit on one look.</summary>
    TimeSpan TimeLimit { get; }

    /// <summary>Looks (again), or joins the look under way; a look still blocked after its time limit isn't repeated
    /// until it returns, and this answers <see cref="Current"/> then. Never throws for the directory's failures.</summary>
    Task<DomainDiscovery> DiscoverAsync(CancellationToken ct = default);
}

/// <summary>
/// CAP-28 discovery: reads the domains from the directory (Active Directory on Windows; a fake in tests). Blocking:
/// <see cref="IOrganizationDomains"/> runs it on its own thread with a time limit.
/// </summary>
public interface IDomainDiscoverySource
{
    /// <summary>The names as the directory gives them, not yet normalized; null when the server isn't joined to a
    /// domain (or isn't Windows). Throws when the directory can't be read.</summary>
    IReadOnlyList<DiscoveredDomain>? Read();
}
