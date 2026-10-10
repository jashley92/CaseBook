using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// ST-01: an attack step's time as it was stated. With <see cref="TimePrecision.Exact"/> (or no timing at all) the
/// step's time is used as given. <see cref="UntilUtc"/> is a window's last day. A step whose time wasn't stated goes
/// after <see cref="AfterStepId"/>, or before every other step when <see cref="First"/> is set.
/// </summary>
public sealed record StepTiming(TimePrecision Precision, DateTimeOffset? UntilUtc = null, Guid? AfterStepId = null, bool First = false)
{
    public static readonly StepTiming Exact = new(TimePrecision.Exact);

    /// <summary>12:00 UTC on the given instant's UTC date: how a stated date is stored, so it reads the same date in
    /// any display zone from UTC−11 to UTC+11.</summary>
    public static DateTimeOffset DateAnchor(DateTimeOffset t) => new(t.UtcDateTime.Date.AddHours(12), TimeSpan.Zero);

    /// <summary>12:00 UTC on a calendar date.</summary>
    public static DateTimeOffset DateAnchor(DateOnly d) => new(d.ToDateTime(new TimeOnly(12, 0)), TimeSpan.Zero);
}

/// <summary>ST-01: the one order for timeline entries: by time, then a step's stated order, then when it was recorded.</summary>
public static class TimelineOrder
{
    public static IOrderedEnumerable<TimelineEntry> InTimelineOrder(this IEnumerable<TimelineEntry> entries) =>
        entries.OrderBy(x => x.OccurredAtUtc).ThenBy(x => x.StepOrder ?? 0).ThenBy(x => x.CreatedAtUtc);
}
