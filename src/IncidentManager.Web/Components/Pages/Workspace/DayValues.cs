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

    /// <summary>The day a stored value stands for (see <see cref="FromUtc"/>).</summary>
    public static DateTime DayOf(DateTimeOffset utc, TimeZoneInfo viewer, TimeZoneInfo organization) =>
        FromUtc(utc, viewer, organization).Date;
}
