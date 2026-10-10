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

    /// <summary>
    /// ST-04: why the case's "activity began" is approximate, or null when it isn't: the first attack step's time is
    /// approximate and the recorded start falls on (or a day either side of) its stated dates, or isn't recorded.
    /// E.g. "the first attack step is between 2026-09-02 and 2026-09-05".
    /// </summary>
    public static string? ActivityBeganCaveat(Case c)
    {
        var first = c.TimelineEntries.Where(e => e.IsCurrent && EventSteps.IsAttack(c, e)).InTimelineOrder().FirstOrDefault();
        if (first is null || !first.IsApproximate) return null;
        if (first.OccurredPrecision == TimePrecision.NotStated) return "the first attack step's time wasn't stated";
        if (c.OccurredAtUtc is { } began)
        {
            var day = DateOnly.FromDateTime(began.UtcDateTime);
            var from = DateOnly.FromDateTime(first.OccurredAtUtc.UtcDateTime);
            var to = DateOnly.FromDateTime((first.OccurredUntilUtc ?? first.OccurredAtUtc).UtcDateTime);
            if (first.OccurredPrecision == TimePrecision.OnOrBefore) from = DateOnly.MinValue;
            if (day < from.AddDays(from == DateOnly.MinValue ? 0 : -1) || day > to.AddDays(1)) return null;
        }
        var stated = Stated(first)!;
        return first.OccurredPrecision switch
        {
            TimePrecision.Day => $"the first attack step is dated {D(first.OccurredAtUtc)}, with no time",
            _ => $"the first attack step is {char.ToLowerInvariant(stated[0])}{stated[1..]}"
        };
    }

    /// <summary>The fixed UTC form reports and prompts use for an exact time.</summary>
    public static string Utc(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);
}
