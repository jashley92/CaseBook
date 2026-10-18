using IncidentManager.Domain.Observables;

namespace IncidentManager.Application.Abstractions;

/// <summary>
/// CAP-28 exclusions: the administered <see cref="RelatedExclusions"/> in force (the organization's domains, its address
/// ranges, and whether free mail is left out), read from the live configuration on each use, so a saved change applies
/// to the next check without a restart.
/// </summary>
public interface IRelatedExclusionsProvider
{
    RelatedExclusions Current { get; }

    /// <summary>
    /// CAP-28 discovery: the domains found on the server's network when they're the ones in force (no administrator has
    /// set the organization's domains, in CaseBook or in the server's settings file), else null. Never stored.
    /// </summary>
    IReadOnlyList<DiscoveredDomain>? DiscoveredInForce => null;
}

/// <summary>CAP-28 exclusions: the settings' keys.</summary>
public static class RelatedExclusionSettings
{
    public const string DomainsKey = "RelatedIndicators:ExcludedDomains";
    public const string RangesKey = "RelatedIndicators:ExcludedRanges";
    public const string FreeMailKey = "RelatedIndicators:ExcludeFreeMail";
}
