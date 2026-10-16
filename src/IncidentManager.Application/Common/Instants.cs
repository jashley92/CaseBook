namespace IncidentManager.Application.Common;

/// <summary>
/// BUG-577: instant arithmetic that can't throw at the ends of the calendar. A stored instant can sit at or near
/// <see cref="DateTimeOffset.MaxValue"/> (a due typed as 9999-12-31) or <see cref="DateTimeOffset.MinValue"/>, where
/// <c>AddMinutes</c> and friends throw and take a whole feed or page down with them.
/// </summary>
public static class Instants
{
    /// <summary><paramref name="t"/> moved by <paramref name="by"/>, held at <see cref="DateTimeOffset.MinValue"/> or
    /// <see cref="DateTimeOffset.MaxValue"/> (in UTC) instead of throwing when the result is out of range.</summary>
    public static DateTimeOffset AddClamped(DateTimeOffset t, TimeSpan by)
    {
        var ticks = t.UtcTicks;
        if (by.Ticks > 0 && ticks > DateTimeOffset.MaxValue.UtcTicks - by.Ticks) return DateTimeOffset.MaxValue;
        if (by.Ticks < 0 && ticks < DateTimeOffset.MinValue.UtcTicks - by.Ticks) return DateTimeOffset.MinValue;
        return t.Add(by);
    }

    /// <summary>The instant <paramref name="local"/> names at <paramref name="offset"/>, in UTC, held at the range ends
    /// when the UTC time falls outside it (local midnight on 0001-01-01 east of Greenwich, say).</summary>
    public static DateTimeOffset FromLocalClamped(DateTime local, TimeSpan offset)
    {
        var utc = local.Ticks - offset.Ticks;
        if (utc < DateTime.MinValue.Ticks) return DateTimeOffset.MinValue;
        if (utc > DateTime.MaxValue.Ticks) return DateTimeOffset.MaxValue;
        return new DateTimeOffset(utc, TimeSpan.Zero);
    }
}
