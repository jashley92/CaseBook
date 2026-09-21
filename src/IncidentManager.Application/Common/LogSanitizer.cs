using System.Text;

namespace IncidentManager.Application.Common;

/// <summary>
/// Neutralises outsider-influenced text before it reaches a single-line sink — a diagnostic log message,
/// an access-log label, a SIEM field — where an embedded CR/LF or control character would let the value
/// forge a second line (log forging, CWE-117) or corrupt the record. Line breaks and other control
/// characters collapse to a single space, runs of whitespace are folded, the result is trimmed, and its
/// length is bounded so a hostile value can neither inject structure nor flood the sink. The companion of
/// <see cref="Csv"/> (which does the same for spreadsheet cells, S-01) for line-oriented sinks.
/// </summary>
public static class LogSanitizer
{
    /// <summary>Default upper bound; long enough for any legitimate file name / label, short enough to bound abuse.</summary>
    public const int DefaultMaxLength = 512;

    /// <summary>
    /// Returns <paramref name="value"/> flattened to a single, control-character-free line: CR/LF, tabs,
    /// other C0/C1 control characters, and the Unicode line/paragraph separators become spaces, adjacent
    /// whitespace is collapsed, the result is trimmed, and it is truncated (with an ellipsis) to
    /// <paramref name="maxLength"/>. Null or whitespace-only input returns <c>null</c>, so an optional
    /// field stays absent rather than becoming an empty string.
    /// </summary>
    public static string? Clean(string? value, int maxLength = DefaultMaxLength)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;

        var sb = new StringBuilder(value.Length);
        var lastWasSpace = false;
        foreach (var ch in value)
        {
            // Control chars (incl. CR/LF/tab) and the Unicode line/paragraph separators all fold to one space.
            // (U+2028/U+2029 are compared by code point — as char literals the lexer would read them as newlines.)
            var isBreakOrSpace = ch == ' ' || char.IsControl(ch) || ch == (char)0x2028 || ch == (char)0x2029;
            if (isBreakOrSpace)
            {
                if (!lastWasSpace) { sb.Append(' '); lastWasSpace = true; }
            }
            else
            {
                sb.Append(ch);
                lastWasSpace = false;
            }
        }

        var cleaned = sb.ToString().Trim();
        if (cleaned.Length == 0) return null;
        if (maxLength > 0 && cleaned.Length > maxLength)
            cleaned = string.Concat(cleaned.AsSpan(0, maxLength), "…");
        return cleaned;
    }
}
