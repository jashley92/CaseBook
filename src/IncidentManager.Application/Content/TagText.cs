using System.Text.RegularExpressions;

namespace IncidentManager.Application.Content;

/// <summary>
/// Entity tags and evidence citations as a person edits them in a plain text box. Stored Markdown carries them as
/// links (<c>[Jane Doe (Finance)](entity:&lt;guid&gt;)</c>, <c>[audit.csv](evidence:&lt;guid&gt;)</c>), which read as noise
/// in a textarea. <see cref="ToEditable"/> shows each as <c>[[Jane Doe (Finance)]]</c>, the same tag syntax the
/// Markdown editors use, and remembers what it pointed at; <see cref="FromEditable"/> turns them back into links on
/// save, so an unchanged text round-trips exactly. A <c>[[name]]</c> typed in the box links to the case's entity of
/// that label or value; one that matches nothing is left as typed.
/// </summary>
public static partial class TagText
{
    [GeneratedRegex(@"\[(?<label>[^\[\]\r\n]+)\]\((?<ref>(?:entity|evidence):[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\)")]
    private static partial Regex Link();

    [GeneratedRegex(@"\[\[(?<label>[^\[\]\r\n]+)\]\]")]
    private static partial Regex Tag();

    /// <summary>The text with its tag links shown as <c>[[label]]</c>; each label's target is added to
    /// <paramref name="refs"/>. BUG-121: when two links share a label (a file that is both cited evidence and an entity,
    /// two entities with the same label), the label keeps each target in the order they appear, joined by
    /// <see cref="Next"/>, so the unchanged text puts each link back where it pointed.</summary>
    public static string? ToEditable(string? markdown, IDictionary<string, string> refs) =>
        markdown is null ? null : Link().Replace(markdown, m =>
        {
            var label = MarkdownText.UnescapeLabel(m.Groups["label"].Value);   // C13: as the reader sees it
            Remember(refs, label, m.Groups["ref"].Value);
            return $"[[{label}]]";
        });

    /// <summary>Records what the next <c>[[label]]</c> in the text points at, after any already recorded for that label
    /// (a citation added at the end of the text, for one).</summary>
    public static void Remember(IDictionary<string, string> refs, string label, string target) =>
        refs[label] = refs.TryGetValue(label, out var known) ? known + Next + target : target;

    private const char Next = '|';

    /// <param name="refs">What each label pointed at when the text was opened (<see cref="ToEditable"/>).</param>
    /// <param name="entities">The case's entities, for a tag typed in the box: id plus its label and value.</param>
    public static string? FromEditable(string? text, IReadOnlyDictionary<string, string> refs,
        IEnumerable<(Guid Id, string? Label, string Value)> entities)
    {
        if (text is null) return null;
        var list = entities.ToList();
        var used = new Dictionary<string, int>(StringComparer.Ordinal);   // how many of each label's targets are taken
        return Tag().Replace(text, m =>
        {
            var label = m.Groups["label"].Value;
            var known = refs.TryGetValue(label, out var exact) ? exact
                : refs.FirstOrDefault(r => r.Key.Equals(label, StringComparison.OrdinalIgnoreCase)).Value;
            string? target;
            if (known is not null)
            {
                // The n-th tag with this label takes its n-th target (the last again if more were typed).
                var targets = known.Split(Next);
                var n = used.GetValueOrDefault(label);
                used[label] = n + 1;
                target = targets[Math.Min(n, targets.Length - 1)];
            }
            else
            {
                // BUG-423: a label wins over another entity's value, and a label saved with spaces round it still matches.
                var name = label.Trim();
                var hit = list.FirstOrDefault(e => Same(e.Label, name));
                if (hit.Id == Guid.Empty) hit = list.FirstOrDefault(e => Same(e.Value, name));
                target = hit.Id != Guid.Empty ? $"entity:{hit.Id}" : null;
            }
            return target is null ? m.Value : $"[{MarkdownText.LinkLabel(label)}]({target})";
        });
    }

    private static bool Same(string? a, string b) => string.Equals(a?.Trim(), b, StringComparison.OrdinalIgnoreCase);

    private static bool Writable(string? s) => !string.IsNullOrWhiteSpace(s) && s.IndexOfAny(['[', ']', '\r', '\n']) < 0;

    /// <summary>What the <c>[[</c> picker inserts for each entity: <c>[[label]]</c>, else <c>[[value]]</c>, when that
    /// text names no other entity (by label or value), so <see cref="FromEditable"/> links it back to this one.
    /// BUG-423: when both are shared with another entity the picker inserts the link itself,
    /// <c>[label](entity:&lt;id&gt;)</c>, which a save keeps as it is. An entity with nothing writable is left out.
    /// BUG-450: <c>Link</c> is that link form for every entity; the picker uses it instead of a <c>[[tag]]</c> whose
    /// text is a label in the box's own refs (see <see cref="RefLabels"/>), which <see cref="FromEditable"/> would
    /// otherwise point at that earlier target (a citation of the same name, a link whose entity was renamed).</summary>
    public static IReadOnlyList<(Guid Id, string Display, string Insert, string Link)> PickerTags(
        IEnumerable<(Guid Id, string? Label, string Value)> entities)
    {
        var list = entities.ToList();
        var named = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);   // how many entities each text names
        foreach (var e in list)
            foreach (var key in new[] { e.Label?.Trim(), e.Value.Trim() }
                         .Where(k => !string.IsNullOrEmpty(k)).Distinct(StringComparer.OrdinalIgnoreCase))
                named[key!] = named.GetValueOrDefault(key!) + 1;
        var tags = new List<(Guid, string, string, string)>();
        foreach (var e in list)
        {
            var label = e.Label?.Trim();
            var value = e.Value.Trim();
            var display = Writable(label) ? label! : Writable(value) ? value : null;
            if (display is null) continue;
            var tag = Writable(label) && named[label!] == 1 ? label
                : Writable(value) && named[value] == 1 ? value : null;
            var link = $"[{MarkdownText.LinkLabel(display)}](entity:{e.Id})";
            tags.Add((e.Id, string.IsNullOrWhiteSpace(label) ? e.Value : label, tag is not null ? $"[[{tag}]]" : link, link));
        }
        return tags;
    }

    /// <summary>BUG-450: the labels a box's <see cref="FromEditable"/> resolves from its refs ahead of the case's
    /// entities, one per line, for the box's <c>data-tag-refs</c>: text-box.js inserts a picked entity as its link
    /// rather than a <c>[[tag]]</c> those refs would claim (compared ignoring case, as <see cref="FromEditable"/> does).</summary>
    public static string RefLabels(IEnumerable<string> labels) =>
        string.Join('\n', labels.Distinct(StringComparer.OrdinalIgnoreCase));
}
