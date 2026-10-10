using System.Globalization;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>
/// ST-01/ST-02: an event step's time in words, as it was stated. One wording for the Record, the briefing, the report,
/// the narrative and the prompts. Stated dates are calendar dates (stored at 12:00 UTC), so they print without a zone.
/// </summary>
public static class StepTime
{
    private static string D(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    /// <summary>The stated time of an approximate step ("2026-03-04 · time not stated", "Between … and …",
    /// "On or before …", "Time not stated"); null when the time is exact.</summary>
    public static string? Stated(TimelineEntry e) => Stated(e.OccurredPrecision, e.OccurredAtUtc, e.OccurredUntilUtc);

    /// <summary>The same, from the stored values (for read models that don't load the entry).</summary>
    public static string? Stated(TimePrecision? precision, DateTimeOffset at, DateTimeOffset? until) => precision switch
    {
        TimePrecision.Day => $"{D(at)} · time not stated",
        TimePrecision.Window => $"Between {D(at)} and {D(until ?? at)}",
        TimePrecision.OnOrBefore => $"On or before {D(at)}",
        TimePrecision.NotStated => "Time not stated",
        _ => null
    };

    /// <summary>A compact form for tight places (chain nodes, pick lists): "2026-03-04", "2026-03-02 to 03-06",
    /// "≤ 2026-03-06", "Not stated"; null when exact.</summary>
    public static string? Short(TimelineEntry e) => e.OccurredPrecision switch
    {
        TimePrecision.Day => D(e.OccurredAtUtc),
        TimePrecision.Window => $"{D(e.OccurredAtUtc)} to {(e.OccurredUntilUtc ?? e.OccurredAtUtc).UtcDateTime.ToString(
            (e.OccurredUntilUtc ?? e.OccurredAtUtc).Year == e.OccurredAtUtc.Year ? "MM-dd" : "yyyy-MM-dd", CultureInfo.InvariantCulture)}",
        TimePrecision.OnOrBefore => $"≤ {D(e.OccurredAtUtc)}",
        TimePrecision.NotStated => "Not stated",
        _ => null
    };

    /// <summary>The step's time as text: the stated wording when approximate, else <paramref name="exact"/> of its time.</summary>
    public static string Text(TimelineEntry e, Func<DateTimeOffset, string> exact) => Stated(e) ?? exact(e.OccurredAtUtc);

    /// <summary>The fixed UTC form reports and prompts use for an exact time.</summary>
    public static string Utc(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);
}
