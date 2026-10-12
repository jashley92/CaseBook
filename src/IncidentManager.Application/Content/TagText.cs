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
            var label = m.Groups["label"].Value;
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
                target = list.FirstOrDefault(e => string.Equals(e.Label, label, StringComparison.OrdinalIgnoreCase)
                                                  || string.Equals(e.Value, label, StringComparison.OrdinalIgnoreCase)) is { Id: var id } && id != Guid.Empty
                    ? $"entity:{id}" : null;
            return target is null ? m.Value : $"[{label}]({target})";
        });
    }
}
