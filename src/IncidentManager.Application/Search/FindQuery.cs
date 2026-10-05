using System.Globalization;
using System.Text.RegularExpressions;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.Observables;

namespace IncidentManager.Application.Search;

/// <summary>How Find read the words left after the filters: it says so above the results.</summary>
public enum FindReadAs { Nothing, Words, CaseNumber, Indicator, Person }

/// <summary>
/// RD-20: a Find query, parsed. Plain words are matched in the record; <c>key:value</c> filters narrow it. The grammar is
/// documented (docs/workflows/find.md) and deterministic: nothing interprets the question but these rules.
/// <list type="bullet">
/// <item><c>entity:VALUE</c> cases, entries and tasks about one entity (exact value, ignoring case)</item>
/// <item><c>status:open</c> / <c>status:closed</c></item>
/// <item><c>class:event|adverse|incident|breach</c> the rung</item>
/// <item><c>type:decision|handoff|adversary|response|note…</c> which record entries (any entry type's name works)</item>
/// <item><c>after:YYYY-MM-DD</c> (that day on), <c>before:YYYY-MM-DD</c> (up to that day) when it happened, in the organization's days</item>
/// <item><c>by:NAME|me</c> who recorded it; <c>owner:NAME|me</c> whose task</item>
/// <item><c>state:NY</c> (or <c>jurisdiction:NY</c>) cases with residents of that state affected</item>
/// <item><c>in:notes</c> include working notes; <c>exercises:yes</c> include exercises</item>
/// <item><c>"a phrase"</c> keeps words together</item>
/// </list>
/// </summary>
public sealed partial record FindQuery
{
    public string Raw { get; init; } = "";
    /// <summary>The words left after the filters; every one must appear (quoted phrases count as one).</summary>
    public IReadOnlyList<string> Terms { get; init; } = [];
    public string? Entity { get; init; }
    public bool? Open { get; init; }
    public bool ClassFilter { get; init; }
    /// <summary>With <see cref="ClassFilter"/>: the rung, or null for a Complex Event (not yet on the ladder).</summary>
    public Classification? Class { get; init; }
    public TimelineKind? EntryKind { get; init; }
    public TimelineEntryType? EntryType { get; init; }
    public DateOnly? After { get; init; }
    public DateOnly? Before { get; init; }
    public string? By { get; init; }
    public string? Owner { get; init; }
    public string? State { get; init; }
    public bool Notes { get; init; }
    public bool Exercises { get; init; }
    /// <summary>Filters it couldn't use, said back to the user rather than silently dropped.</summary>
    public IReadOnlyList<string> Unread { get; init; } = [];

    /// <summary>The words as one string (for reading them as a number, an indicator or a person).</summary>
    public string Text => string.Join(' ', Terms);

    public bool HasFilters => Entity is not null || Open is not null || ClassFilter || EntryKind is not null || EntryType is not null
                              || After is not null || Before is not null || By is not null || Owner is not null || State is not null;

    public bool IsEmpty => Terms.Count == 0 && !HasFilters;

    private static readonly string[] Keys =
        ["entity", "status", "class", "type", "after", "before", "by", "owner", "state", "jurisdiction", "in", "exercises"];

    public static FindQuery Parse(string? raw)
    {
        raw = (raw ?? "").Trim();
        var terms = new List<string>();
        var unread = new List<string>();
        var q = new FindQuery { Raw = raw };

        foreach (Match m in TokenRx().Matches(raw))
        {
            var key = m.Groups["k"].Success ? m.Groups["k"].Value.ToLowerInvariant() : null;
            var val = (m.Groups["qv"].Success ? m.Groups["qv"].Value : m.Groups["v"].Value).Trim();
            if (key is null || !Keys.Contains(key))
            {
                // Not a filter: a word or a phrase. A "key:" we don't know stays a word (it may be a URL or an account).
                var word = m.Groups["qv"].Success && key is null ? val : m.Value.Trim('"');
                if (word.Length > 0) terms.Add(word);
                continue;
            }
            if (val.Length == 0) { unread.Add($"{key}: needs a value"); continue; }
            switch (key)
            {
                case "entity": q = q with { Entity = IocObservable.Refang(val) }; break;
                case "status":
                    if (val.Equals("open", StringComparison.OrdinalIgnoreCase)) q = q with { Open = true };
                    else if (val.Equals("closed", StringComparison.OrdinalIgnoreCase)) q = q with { Open = false };
                    else unread.Add($"status:{val} (use open or closed)");
                    break;
                case "class":
                    if (ParseClass(val) is { } cls) q = q with { ClassFilter = true, Class = cls.Value };
                    else unread.Add($"class:{val} (use event, adverse, incident or breach)");
                    break;
                case "type":
                    if (ParseType(val) is { } t) q = q with { EntryKind = t.Kind, EntryType = t.Type };
                    else unread.Add($"type:{val}");
                    break;
                case "after":
                case "before":
                    if (DateOnly.TryParseExact(val, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d))
                        q = key == "after" ? q with { After = d } : q with { Before = d };
                    else unread.Add($"{key}:{val} (use a date like 2026-01-31)");
                    break;
                case "by": q = q with { By = val }; break;
                case "owner": q = q with { Owner = val }; break;
                case "state":
                case "jurisdiction":
                    if (StateRx().IsMatch(val)) q = q with { State = val.ToUpperInvariant() };
                    else unread.Add($"{key}:{val} (use a two-letter code like NY)");
                    break;
                case "in":
                    if (val.Equals("notes", StringComparison.OrdinalIgnoreCase)) q = q with { Notes = true };
                    else unread.Add($"in:{val} (only in:notes)");
                    break;
                case "exercises":
                    q = q with { Exercises = val.ToLowerInvariant() is "yes" or "true" or "include" or "on" };
                    break;
            }
        }
        return q with { Terms = terms, Unread = unread };
    }

    /// <summary>
    /// The query with one filter set to <paramref name="value"/>, or removed when it's null: how the filters beside the
    /// results edit the question the user can see.
    /// </summary>
    public static string WithFilter(string? raw, string key, string? value)
    {
        var keys = key is "state" or "jurisdiction" ? new[] { "state", "jurisdiction" } : [key];
        var kept = TokenRx().Matches(raw ?? "")
            .Where(m => !(m.Groups["k"].Success && keys.Contains(m.Groups["k"].Value.ToLowerInvariant())))
            .Select(m => m.Value.Trim());
        var tokens = kept.ToList();
        if (value is not null) tokens.Add($"{key}:{(value.Contains(' ') ? $"\"{value}\"" : value)}");
        return string.Join(' ', tokens.Where(t => t.Length > 0));
    }

    private static (Classification? Value, bool _)? ParseClass(string v) => v.ToLowerInvariant() switch
    {
        "event" or "complex" or "complex-event" or "complexevent" or "none" => (null, true),
        "adverse" or "adverse-event" or "adverseevent" => (Classification.AdverseEvent, true),
        "incident" => (Classification.Incident, true),
        "breach" => (Classification.Breach, true),
        _ => null
    };

    private static (TimelineKind? Kind, TimelineEntryType? Type)? ParseType(string v)
    {
        switch (v.ToLowerInvariant())
        {
            case "adversary": case "attack": case "step": return (TimelineKind.Event, null);
            case "response": return (TimelineKind.Investigation, null);
            case "decisions": return (null, TimelineEntryType.Decision);
        }
        return Enum.TryParse<TimelineEntryType>(v.Replace("-", ""), ignoreCase: true, out var t) && Enum.IsDefined(t)
            ? (null, t) : null;
    }

    /// <summary>How the words read, before any lookup: a case number, an indicator, or words (a person needs the directory).</summary>
    public static (FindReadAs As, EntityType? Type) ReadShape(string text)
    {
        if (text.Length == 0) return (FindReadAs.Nothing, null);
        if (CaseNumberRx().IsMatch(text)) return (FindReadAs.CaseNumber, null);
        if (!text.Contains(' '))
        {
            var t = IocObservable.DetectType(text);
            if (t != EntityType.Other) return (FindReadAs.Indicator, t);
            if (text.Contains('\\')) return (FindReadAs.Indicator, EntityType.Account);   // DOMAIN\user
        }
        return (FindReadAs.Words, null);
    }

    // key:value, key:"quoted value", "a phrase", or a bare word.
    [GeneratedRegex("""(?:(?<k>[A-Za-z]+):(?:"(?<qv>[^"]*)"|(?<v>\S*)))|(?:"(?<qv>[^"]*)")|(?<v>\S+)""")]
    private static partial Regex TokenRx();

    // 2026-124, CE-2026-10-04, 2026-01_Phishing_Wave: a year then a sequence, optionally prefixed.
    [GeneratedRegex(@"^([A-Za-z]{1,6}-)?\d{4}-\d{1,4}(-\d{1,4})?(_\S*)?$")]
    private static partial Regex CaseNumberRx();

    [GeneratedRegex("^[A-Za-z]{2}$")]
    private static partial Regex StateRx();
}
