namespace IncidentManager.Web.Components.Pages.Workspace;

/// <summary>
/// WF-64: a due date or target picked as a bare date (no time) means the end of that day on the organization's calendar
/// (23:59 there), not in the zone of whoever picked it. A day is the organization's, so the report, the CSV and every
/// viewer read the day that was picked; stored at 23:59 in the picker's own zone, a date picked in New York printed a day
/// late for a London organization. A value with a time keeps that time in the viewer's zone, as before (F-20).
/// </summary>
public static class DayValues
{
    public static readonly TimeSpan EndOfDay = new(23, 59, 0);

    public static DateTimeOffset ToUtc(DateTime date, TimeOnly? time, TimeZoneInfo viewer, TimeZoneInfo organization) =>
        time is { } t
            ? WallClock.ToUtc(date.Date + t.ToTimeSpan(), viewer)
            : WallClock.ToUtc(date.Date + EndOfDay, organization);

    /// <summary>A stored value back as the form shows it: a bare date when it's 23:59 on the organization's calendar,
    /// else the date and time in the viewer's zone.</summary>
    public static (DateTime Date, TimeOnly? Time) FromUtc(DateTimeOffset utc, TimeZoneInfo viewer, TimeZoneInfo organization)
    {
        var org = WallClock.ToWall(utc, organization);
        if (org.TimeOfDay == EndOfDay) return (org.Date, null);
        var wall = WallClock.ToWall(utc, viewer);
        return (wall.Date, TimeOnly.FromTimeSpan(wall.TimeOfDay));
    }

    /// <summary>
    /// C3 (BUG-571): the due to save from a form seeded with a stored one. A date and time left as
    /// <paramref name="shown"/> (the time to the minute) keep <paramref name="stored"/>; converting them back read a due in
    /// the repeated autumn hour as standard time, so editing only the title moved the due an hour. Changed, they are read
    /// as typed (a bare date is the end of that day, WF-64); no date is no due.
    /// </summary>
    public static DateTimeOffset? Kept(DateTime? date, TimeOnly? time, (DateTime Date, TimeOnly? Time)? shown,
        DateTimeOffset? stored, TimeZoneInfo viewer, TimeZoneInfo organization)
    {
        if (date is not { } d) return null;
        if (stored is { } kept && shown is { } s && d.Date == s.Date.Date && ToMinute(time) == ToMinute(s.Time)) return kept;
        return ToUtc(d, time, viewer, organization);
    }

    private static TimeOnly? ToMinute(TimeOnly? t) => t is { } v ? new TimeOnly(v.Hour, v.Minute) : null;

    /// <summary>The day a stored value stands for (see <see cref="FromUtc"/>).</summary>
    public static DateTime DayOf(DateTimeOffset utc, TimeZoneInfo viewer, TimeZoneInfo organization) =>
        FromUtc(utc, viewer, organization).Date;
}
