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
}

/// <summary>CAP-28 exclusions: the settings' keys.</summary>
public static class RelatedExclusionSettings
{
    public const string DomainsKey = "RelatedIndicators:ExcludedDomains";
    public const string RangesKey = "RelatedIndicators:ExcludedRanges";
    public const string FreeMailKey = "RelatedIndicators:ExcludeFreeMail";
}
