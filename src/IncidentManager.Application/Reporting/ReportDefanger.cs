using System.Text.RegularExpressions;
using IncidentManager.Application.Content;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.Observables;

namespace IncidentManager.Application.Reporting;

/// <summary>
/// PROD-44: defangs indicators in the human-readable reports (hxxp://, [.], [at]), so a forwarded report can't turn a
/// malicious URL, domain, IP or address into a clickable link — Outlook and Word auto-link plain text. Structured
/// values are defanged by entity type; free text (summary, timeline, notes, review) has the case's own indicator
/// values, any http(s) URL and any bare IPv4 address defanged wherever they appear. One regex pass per string, so
/// already-defanged text is never defanged twice. Machine exports (IOC CSV, STIX, import) never go through this.
/// </summary>
public sealed class ReportDefanger
{
    /// <summary>Entity types whose values a mail client or word processor would turn into a link.</summary>
    private static readonly HashSet<EntityType> Linkable =
        [EntityType.Url, EntityType.Domain, EntityType.IpAddress, EntityType.EmailAddress];

    /// <summary>A defanger that changes nothing (the admin turned defanging off).</summary>
    public static readonly ReportDefanger Off = new(enabled: false, knownValues: []);

    private readonly bool _enabled;
    private readonly Regex? _pattern;

    private ReportDefanger(bool enabled, IEnumerable<string> knownValues)
    {
        _enabled = enabled;
        if (!enabled) return;
        // Longest first, so a URL wins over the domain inside it. Then any http(s) URL, then a bare IPv4 address.
        var known = knownValues
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(v => v.Length)
            .Select(Regex.Escape);
        var alternatives = known
            .Append(@"\bhttps?://[^\s<>""')\]]+")
            .Append(@"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b");
        _pattern = new Regex(string.Join("|", alternatives), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(2));
    }

    /// <summary>The defanger for a case: its linkable indicator values are known, so they're caught in prose too.</summary>
    public static ReportDefanger For(IEnumerable<CaseEntity> entities, bool enabled) =>
        enabled
            ? new ReportDefanger(true, entities.Where(e => Linkable.Contains(e.Type)).Select(e => e.Value))
            : Off;

    public bool Enabled => _enabled;

    /// <summary>A structured indicator value, defanged when its type is linkable.</summary>
    public string Value(EntityType type, string value) =>
        _enabled && Linkable.Contains(type) ? IocObservable.Defang(value) : value;

    /// <summary>Free text with every indicator in it defanged.</summary>
    public string Text(string text) =>
        !_enabled || string.IsNullOrEmpty(text) || _pattern is null ? text : _pattern.Replace(text, m => IocObservable.Defang(m.Value));

    /// <inheritdoc cref="Text(string)"/>
    public string? NullableText(string? text) => text is null ? null : Text(text);

    /// <summary>Formatted prose with every run's text defanged (formatting kept).</summary>
    public IReadOnlyList<RichBlock> Blocks(IReadOnlyList<RichBlock> blocks) =>
        !_enabled ? blocks : blocks.Select(b => b with { Runs = b.Runs.Select(r => r with { Text = Text(r.Text) }).ToList() }).ToList();
}
