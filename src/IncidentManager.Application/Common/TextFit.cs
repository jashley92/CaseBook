namespace IncidentManager.Application.Common;

/// <summary>
/// Shortens text to a stored or shown length (C12). One place for what hand-rolled <c>s[..n] + "…"</c> caps kept
/// getting wrong: the result, ellipsis included, is never longer than the limit (so it fits the column it was cut
/// for), and a cut never splits a surrogate pair (half an emoji is an invalid string to SQL Server and to JSON).
/// </summary>
public static class TextFit
{
    public const string Ellipsis = "…";

    /// <summary>
    /// <paramref name="text"/> when it is at most <paramref name="max"/> characters; otherwise its start followed by
    /// <paramref name="marker"/> (an ellipsis by default; pass <c>""</c> for a plain cut), <paramref name="max"/>
    /// characters in all. Null stays null.
    /// </summary>
    [return: System.Diagnostics.CodeAnalysis.NotNullIfNotNull(nameof(text))]
    public static string? Cap(string? text, int max, string marker = Ellipsis)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(max);
        if (text is null || text.Length <= max) return text;
        if (marker.Length >= max) marker = "";
        var keep = max - marker.Length;
        if (keep > 0 && char.IsHighSurrogate(text[keep - 1])) keep--;   // never leave half a pair
        return string.Concat(text.AsSpan(0, keep), marker);
    }
}
