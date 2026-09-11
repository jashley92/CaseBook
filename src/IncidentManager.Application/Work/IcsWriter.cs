using System.Globalization;
using System.Text;

namespace IncidentManager.Application.Work;

/// <summary>One event to emit into an iCalendar feed.</summary>
public sealed record IcsEvent(
    string Uid, DateTimeOffset StartUtc, string Summary, string? Description, string? Url, bool Overdue);

/// <summary>
/// Minimal, dependency-free iCalendar (RFC 5545) writer for the agenda calendar feed (E-39). Emits UTC
/// timestamps only, folds nothing (lines are short), and escapes text per §3.3.11. Kept pure and in the
/// Application layer so it is unit-testable and reused by the download and the subscribable feed.
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
        sb.Append("X-WR-CALNAME:").Append(Escape(calendarName)).Append("\r\n");

        var stamp = Stamp(nowUtc);
        foreach (var e in events)
        {
            sb.Append("BEGIN:VEVENT\r\n");
            sb.Append("UID:").Append(Escape(e.Uid)).Append("\r\n");
            sb.Append("DTSTAMP:").Append(stamp).Append("\r\n");
            sb.Append("DTSTART:").Append(Stamp(e.StartUtc)).Append("\r\n");
            // A follow-up item is a point-in-time deadline; give it a nominal 30-minute block.
            sb.Append("DTEND:").Append(Stamp(e.StartUtc.AddMinutes(30))).Append("\r\n");
            sb.Append("SUMMARY:").Append(Escape(e.Summary)).Append("\r\n");
            if (!string.IsNullOrWhiteSpace(e.Description))
                sb.Append("DESCRIPTION:").Append(Escape(e.Description!)).Append("\r\n");
            if (!string.IsNullOrWhiteSpace(e.Url))
                sb.Append("URL:").Append(Escape(e.Url!)).Append("\r\n");
            if (e.Overdue) sb.Append("CATEGORIES:OVERDUE\r\n");
            sb.Append("END:VEVENT\r\n");
        }

        sb.Append("END:VCALENDAR\r\n");
        return sb.ToString();
    }

    private static string Stamp(DateTimeOffset t) =>
        t.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);

    // RFC 5545 §3.3.11: escape backslash, semicolon, comma; newlines become \n.
    private static string Escape(string s) => s
        .Replace("\\", "\\\\")
        .Replace(";", "\\;")
        .Replace(",", "\\,")
        .Replace("\r\n", "\\n")
        .Replace("\n", "\\n")
        .Replace("\r", "\\n");
}
