using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Web.Services;

/// <summary>How the Administration pages read and label settings: shared by the settings sections, Diagnostics and search.</summary>
public static class AdminSettingsDisplay
{
    /// <summary>
    /// A setting's value in the server's configuration as its section edits it: a list one entry per line (a list binds as
    /// <c>key:0</c>, <c>key:1</c>, so reading <c>key</c> alone finds nothing), anything else as written.
    /// </summary>
    public static string? ConfiguredValue(IConfiguration config, string key) =>
        SettingsCatalog.ByKey.TryGetValue(key, out var def) && def.Kind == SettingKind.MultiText
        && config.GetSection(key).Get<string[]>() is { Length: > 0 } list
            ? string.Join("\n", list)
            : config[key];

    /// <summary>
    /// A setting's label with the organization's name for any severity in it ("Stale after: SEV-1 (days)"), so a renamed
    /// level reads the same everywhere. The severity labels' own rows keep the built-in name: that's what each renames.
    /// </summary>
    public static string Label(SettingDefinition def, ISeverityLabels labels)
    {
        var parts = def.Key.Split(':');
        return parts is not ["Severity", ..] && parts.Length > 1 && EnumNames.TryParse<Severity>(parts[^1], out var sev)
            ? def.Label.Replace(sev.ToString(), labels.For(sev))
            : def.Label;
    }
}
