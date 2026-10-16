using System.Globalization;
using System.Text;

namespace IncidentManager.Application.Work;

/// <summary>One event to emit into an iCalendar feed.</summary>
public sealed record IcsEvent(
    string Uid, DateTimeOffset StartUtc, string Summary, string? Description, string? Url, bool Overdue);

/// <summary>
/// Minimal, dependency-free iCalendar (RFC 5545) writer for the agenda calendar feed (E-39). Emits UTC
/// timestamps only, escapes text per §3.3.11, and folds lines longer than 75 octets (§3.1; BUG-212: a task title
/// with its case number runs to hundreds). Kept pure and in the Application layer so it is unit-testable and reused
/// by the download and the subscribable feed.
/// </summary>
public static class IcsWriter
{
    private const string ProdId = "-//CaseBook//Agenda//EN";

    /// <summary>Serializes a calendar with the given events. <paramref name="nowUtc"/> stamps DTSTAMP.</summary>
    public static string Write(string calendarName, IEnumerable<IcsEvent> events, DateTimeOffset nowUtc)
    {
        var sb = new StringBuilder();
        sb.Append("BEGIN:VCALENDAR\r\n");
        sb.Append("VERSION:2.0\r\n");
        sb.Append("PRODID:").Append(ProdId).Append("\r\n");
        sb.Append("CALSCALE:GREGORIAN\r\n");
        sb.Append("METHOD:PUBLISH\r\n");
        Line(sb, "X-WR-CALNAME", Escape(calendarName));

        var stamp = Stamp(nowUtc);
        foreach (var e in events)
        {
            sb.Append("BEGIN:VEVENT\r\n");
            Line(sb, "UID", Escape(e.Uid));
            sb.Append("DTSTAMP:").Append(stamp).Append("\r\n");
            sb.Append("DTSTART:").Append(Stamp(e.StartUtc)).Append("\r\n");
            // A follow-up item is a point-in-time deadline; give it a nominal 30-minute block. BUG-577: held at the last
            // instant for a due at the end of 9999, which made the whole feed throw for everyone who could see the task.
            sb.Append("DTEND:").Append(Stamp(Common.Instants.AddClamped(e.StartUtc, TimeSpan.FromMinutes(30)))).Append("\r\n");
            Line(sb, "SUMMARY", Escape(e.Summary));
            if (!string.IsNullOrWhiteSpace(e.Description))
                Line(sb, "DESCRIPTION", Escape(e.Description!));
            // BUG-212: a URI value, not text, so it isn't text-escaped (a "," or ";" in it would be corrupted).
            if (!string.IsNullOrWhiteSpace(e.Url))
                Line(sb, "URL", e.Url!.Replace("\r", "").Replace("\n", ""));
            if (e.Overdue) sb.Append("CATEGORIES:OVERDUE\r\n");
            sb.Append("END:VEVENT\r\n");
        }

        sb.Append("END:VCALENDAR\r\n");
        return sb.ToString();
    }

    // One content line, folded so no physical line passes 75 octets of UTF-8: each continuation starts with a space.
    // A character is never split across lines.
    private static void Line(StringBuilder sb, string name, string value)
    {
        const int Limit = 75;
        var line = name + ":" + value;
        var used = 0;
        foreach (var rune in line.EnumerateRunes())
        {
            var size = rune.Utf8SequenceLength;
            if (used + size > Limit)
            {
                sb.Append("\r\n ");
                used = 1;
            }
            sb.Append(rune.ToString());
            used += size;
        }
        sb.Append("\r\n");
    }

    private static string Stamp(DateTimeOffset t) =>
        t.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);

    // RFC 5545 §3.3.11: escape backslash, semicolon, comma; newlines become \n. C13: other control characters (which
    // the TEXT grammar doesn't allow, and some clients reject the whole feed over) are left out; a tab stays.
    private static string Escape(string s) => DropControls(s)
        .Replace("\\", "\\\\")
        .Replace(";", "\\;")
        .Replace(",", "\\,")
        .Replace("\r\n", "\\n")
        .Replace("\n", "\\n")
        .Replace("\r", "\\n");

    private static string DropControls(string s) =>
        s.Any(c => char.IsControl(c) && c is not ('\t' or '\r' or '\n'))
            ? string.Concat(s.Where(c => !char.IsControl(c) || c is '\t' or '\r' or '\n'))
            : s;
}
