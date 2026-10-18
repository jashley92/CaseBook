using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Observables;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Configuration;

/// <summary>
/// CAP-28 exclusions: reads <c>RelatedIndicators:*</c> from the live configuration on each use (as
/// <see cref="Notifications.ConfigurationExerciseEscalationPolicy"/> does), so an administered change applies to the next
/// check without a restart. Nothing is kept between calls: a handful of entries parse in microseconds, and a copy kept
/// would need its own reload order (C21).
/// <para>CAP-28 discovery: while the organization's domains aren't set anywhere (no in-app value, nothing in the
/// server's settings file), the domains found on the server's network are the ones in force. Once an administrator saves
/// a value, blank included, theirs wins.</para>
/// </summary>
public sealed class ConfigurationRelatedExclusions(IConfiguration config, IOrganizationDomains? discovered = null) : IRelatedExclusionsProvider
{
    public RelatedExclusions Current => RelatedExclusions.From(
        List(RelatedExclusionSettings.DomainsKey) ?? DiscoveredNames(),
        List(RelatedExclusionSettings.RangesKey) ?? RelatedExclusions.DefaultRanges,
        !bool.TryParse(config[RelatedExclusionSettings.FreeMailKey]?.Trim(), out var freeMail) || freeMail);

    public IReadOnlyList<DiscoveredDomain>? DiscoveredInForce =>
        discovered is not null && List(RelatedExclusionSettings.DomainsKey) is null && OwnFound() is { Count: > 0 } found
            ? found
            : null;

    private IReadOnlyList<string> DiscoveredNames() => OwnFound().Select(d => d.Name).ToList();

    // Owner's call (2026-10-18): only the organization's own domains (this one, its forest root, the forest's others) are
    // in force while the setting is unset. A trusted partner's domain isn't necessarily noise, so it's only offered under
    // "Use these" for an administrator to accept.
    private List<DiscoveredDomain> OwnFound() =>
        discovered?.Current.Domains.Where(d => d.Source != DiscoveredDomainSource.Trusted).ToList() ?? [];

    // A list setting: indexed children (an in-app value, or a JSON array in a settings file), or one string written by hand
    // ("10.0.0.0/8, fd00::/8"); null when it isn't set anywhere, so the default applies. An in-app value saved blank is
    // set: its children are there, blank (DbSettingsConfiguration masks the file's list), and it means none.
    // CAP-28 review (F1): the children first. The in-app value is only ever children, so a single string in the settings
    // file or an environment variable (RelatedIndicators__ExcludedRanges) beat it, and beat an in-app "none", while the
    // page said Database. The single string is read only when there are no children anywhere.
    private IReadOnlyList<string>? List(string key)
    {
        var section = config.GetSection(key);
        var children = section.GetChildren().ToList();
        if (children.Count > 0)
            return children.Select(c => c.Value?.Trim()).Where(v => !string.IsNullOrEmpty(v)).Select(v => v!).ToList();
        if (section.Value is { } flat)
            return flat.Split(['\n', '\r', ',', ';', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        // A settings file's empty array ("ExcludedDomains": []) is the key with no value and no children: set, to none.
        return ListedEmpty(key) ? [] : null;
    }

    private bool ListedEmpty(string key) =>
        config is IConfigurationRoot root && root.Providers.Any(p => p.TryGet(key, out var v) && v is null);
}
