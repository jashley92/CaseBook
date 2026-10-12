using System.Text;
using System.Xml;

namespace IncidentManager.Infrastructure.Reporting;

/// <summary>
/// BUG-42: case text can hold characters XML 1.0 can't (most control characters, e.g. a terminal bell pasted into an
/// import), and one of them made the whole Word document fail to save, so every later report for that case failed.
/// They're dropped; tab, line feed and carriage return are kept, as are valid surrogate pairs.
/// </summary>
internal static class XmlSafe
{
    public static string Clean(string? text)
    {
        if (string.IsNullOrEmpty(text)) return text ?? "";
        var i = 0;
        while (i < text.Length && Valid(text, i, out var n)) i += n;
        if (i == text.Length) return text;   // the common case: nothing to drop

        var sb = new StringBuilder(text.Length);
        sb.Append(text, 0, i);
        while (i < text.Length)
        {
            if (Valid(text, i, out var n)) sb.Append(text, i, n);
            i += n;
        }
        return sb.ToString();
    }

    private static bool Valid(string s, int i, out int length)
    {
        if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { length = 2; return true; }
        length = 1;
        return XmlConvert.IsXmlChar(s[i]);
    }
}
