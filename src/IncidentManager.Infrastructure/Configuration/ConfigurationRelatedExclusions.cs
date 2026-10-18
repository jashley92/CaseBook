using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Observables;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Configuration;

/// <summary>
/// CAP-28 exclusions: reads <c>RelatedIndicators:*</c> from the live configuration on each use (as
/// <see cref="Notifications.ConfigurationExerciseEscalationPolicy"/> does), so an administered change applies to the next
/// check without a restart. Nothing is kept between calls: a handful of entries parse in microseconds, and a copy kept
/// would need its own reload order (C21).
/// </summary>
public sealed class ConfigurationRelatedExclusions(IConfiguration config) : IRelatedExclusionsProvider
{
    public RelatedExclusions Current => RelatedExclusions.From(
        List(RelatedExclusionSettings.DomainsKey) ?? [],
        List(RelatedExclusionSettings.RangesKey) ?? RelatedExclusions.DefaultRanges,
        !bool.TryParse(config[RelatedExclusionSettings.FreeMailKey]?.Trim(), out var freeMail) || freeMail);

    // A list setting: indexed children (an in-app value, or a JSON array in a settings file), or one string written by hand
    // ("10.0.0.0/8, fd00::/8"); null when it isn't set anywhere, so the default applies. An in-app value saved blank is
    // set: its children are there, blank (DbSettingsConfiguration masks the file's list), and it means none.
    private IReadOnlyList<string>? List(string key)
    {
        var section = config.GetSection(key);
        if (section.Value is { } flat)
            return flat.Split(['\n', '\r', ',', ';', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var children = section.GetChildren().ToList();
        if (children.Count == 0) return null;
        return children.Select(c => c.Value?.Trim()).Where(v => !string.IsNullOrEmpty(v)).Select(v => v!).ToList();
    }
}
