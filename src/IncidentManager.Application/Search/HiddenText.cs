namespace IncidentManager.Application.Search;

/// <summary>
/// WF-84: stored Markdown holds link targets the reader never sees (<c>[name](entity:&lt;id&gt;)</c>, <c>evidence:</c>, a
/// GUID's hex). A word that could be part of one is checked again against the text as shown before a match counts. Only
/// text that holds a link (<see cref="LinkMark"/>) can hide anything, so only that is read back (BUG-272), and at most
/// <see cref="MaxRecheck"/> rows of it, newest first; any beyond that are kept, as a match the reader may see.
/// </summary>
public static class HiddenText
{
    /// <summary>What every Markdown link has between its text and its target.</summary>
    public const string LinkMark = "](";

    /// <summary>The most rows of linked text read back per kind of result.</summary>
    public const int MaxRecheck = 500;

    private static readonly string[] LinkSchemes = ["entity:", "evidence:", "entry:", "note:"];

    /// <summary>A word that a link target could hold: part of a scheme name, or hex digits and dashes (a GUID's).</summary>
    public static bool CouldBeHidden(string term) =>
        LinkSchemes.Any(s => s.Contains(term, StringComparison.Ordinal))
        || (term.Length >= 2 && term.All(ch => ch is (>= '0' and <= '9') or (>= 'a' and <= 'f') or '-'));

    /// <summary>Whether every (lower-case) word is in the texts as the reader sees them: <paramref name="plain"/> as it is,
    /// <paramref name="markdown"/> with links shown by their names.</summary>
    public static bool Shows(IReadOnlyList<string> terms, string? plain, params string?[] markdown)
    {
        var shown = string.Join('\n', markdown.Where(t => t is not null).Select(t => Content.RichText.ToText(t)).Prepend(plain ?? ""))
            .ToLowerInvariant();
        return terms.All(t => shown.Contains(t, StringComparison.Ordinal));
    }
}
