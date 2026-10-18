using System.Globalization;
using System.Text;

namespace IncidentManager.Application.Search;

/// <summary>
/// CAP-22: one search word (or quoted phrase) as a SQL Server full-text search condition, so typing as you go still finds:
/// <c>lsa</c> becomes <c>"lsa*"</c>, the words that start with it. Everything the user typed goes inside one double-quoted
/// prefix term, where <c>AND</c>, <c>OR</c>, <c>NEAR</c>, <c>NOT</c>, <c>~</c>, <c>&amp;</c>, <c>|</c> and <c>!</c> are
/// words, never operators, and nothing the user types can end the quotes. A phrase (<c>"lateral movement"</c>) stays a
/// phrase, each of its words a prefix. Null when there's no word in it (only punctuation, or nothing), or it's too long
/// for a word: that one is matched as a substring, as without full-text.
/// </summary>
public static class FullTextCondition
{
    /// <summary>The longest term sent as a full-text condition; a longer one is matched as a substring.</summary>
    public const int MaxLength = 200;

    public static string? For(string? term)
    {
        if (string.IsNullOrWhiteSpace(term)) return null;
        var sb = new StringBuilder(term.Length + 3);
        var hasWord = false;
        var space = false;
        foreach (var rune in term.EnumerateRunes())
        {
            // A double quote would end the term, and a * inside it is a stray wildcard: both become a word break, as
            // white space, control characters and broken text (a lone surrogate) do. Everything else is the word breaker's.
            var category = Rune.GetUnicodeCategory(rune);
            if (rune.Value is '"' or '*' || rune == Rune.ReplacementChar || Rune.IsWhiteSpace(rune)
                || category is UnicodeCategory.Control or UnicodeCategory.Format
                    or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned)
            {
                space = sb.Length > 0;
                continue;
            }
            if (space) sb.Append(' ');
            space = false;
            sb.Append(rune.ToString());
            if (Rune.IsLetterOrDigit(rune)) hasWord = true;
        }
        if (!hasWord || sb.Length > MaxLength) return null;
        return "\"" + sb + "*\"";
    }
}
