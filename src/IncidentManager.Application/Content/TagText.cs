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
    /// <paramref name="refs"/> (the first wins when two links share a label).</summary>
    public static string? ToEditable(string? markdown, IDictionary<string, string> refs) =>
        markdown is null ? null : Link().Replace(markdown, m =>
        {
            var label = m.Groups["label"].Value;
            refs.TryAdd(label, m.Groups["ref"].Value);
            return $"[[{label}]]";
        });

    /// <param name="refs">What each label pointed at when the text was opened (<see cref="ToEditable"/>).</param>
    /// <param name="entities">The case's entities, for a tag typed in the box: id plus its label and value.</param>
    public static string? FromEditable(string? text, IReadOnlyDictionary<string, string> refs,
        IEnumerable<(Guid Id, string? Label, string Value)> entities)
    {
        if (text is null) return null;
        var list = entities.ToList();
        return Tag().Replace(text, m =>
        {
            var label = m.Groups["label"].Value;
            var target = refs.TryGetValue(label, out var known) ? known
                : refs.FirstOrDefault(r => r.Key.Equals(label, StringComparison.OrdinalIgnoreCase)).Value
                  ?? (list.FirstOrDefault(e => string.Equals(e.Label, label, StringComparison.OrdinalIgnoreCase)
                                               || string.Equals(e.Value, label, StringComparison.OrdinalIgnoreCase)) is { Id: var id } && id != Guid.Empty
                      ? $"entity:{id}" : null);
            return target is null ? m.Value : $"[{label}]({target})";
        });
    }
}
