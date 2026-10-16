using System.Text;

namespace IncidentManager.Application.Content;

/// <summary>
/// C13: text placed into Markdown that the app writes itself (a tag link's label). In a link label a backslash escapes
/// the character after it, so a label such as <c>C:\Temp\</c> escaped the closing bracket and the tag rendered as raw
/// text instead of a chip. Backslashes and brackets are escaped going in and unescaped coming back, so a label
/// round-trips exactly.
/// </summary>
public static class MarkdownText
{
    /// <summary><paramref name="label"/> escaped for the text of a <c>[label](target)</c> link.</summary>
    public static string LinkLabel(string label)
    {
        if (label.IndexOfAny(['\\', '[', ']']) < 0) return label;
        var sb = new StringBuilder(label.Length + 4);
        foreach (var c in label)
        {
            if (c is '\\' or '[' or ']') sb.Append('\\');
            sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>The label text of a link as a reader sees it: a backslash before ASCII punctuation is dropped, as
    /// CommonMark renders it. The inverse of <see cref="LinkLabel"/>.</summary>
    public static string UnescapeLabel(string label)
    {
        if (!label.Contains('\\')) return label;
        var sb = new StringBuilder(label.Length);
        var i = 0;
        while (i < label.Length)
        {
            var escaped = label[i] == '\\' && i + 1 < label.Length && IsAsciiPunctuation(label[i + 1]);
            if (escaped) i++;   // drop the backslash, keep what it escaped
            sb.Append(label[i]);
            i++;
        }
        return sb.ToString();
    }

    // CommonMark's escapable characters.
    private static bool IsAsciiPunctuation(char c) => c is (>= '!' and <= '/') or (>= ':' and <= '@') or (>= '[' and <= '`') or (>= '{' and <= '~');
}
