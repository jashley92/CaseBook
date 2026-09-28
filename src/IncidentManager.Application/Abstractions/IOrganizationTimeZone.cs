namespace IncidentManager.Application.Abstractions;

/// <summary>
/// The organization's reporting time zone (<c>Organization:TimeZone</c>, an IANA id such as America/New_York).
/// It decides where calendar periods begin, for example which month a case opened in on the dashboard trend.
/// Daylight saving follows the zone. Stored timestamps, the audit trail and exports stay in UTC.
/// </summary>
public interface IOrganizationTimeZone
{
    TimeZoneInfo Current { get; }
}

/// <summary>Calendar months in a given time zone, as UTC instants for querying.</summary>
public static class ZonedMonths
{
    /// <summary>The instant the month begins at local midnight in <paramref name="zone"/>.</summary>
    public static DateTimeOffset StartUtc(int year, int month, TimeZoneInfo zone)
    {
        var local = new DateTime(year, month, 1, 0, 0, 0, DateTimeKind.Unspecified);
        // A zone that springs forward at midnight has no 00:00 that day; the month then starts when the clock resumes.
        if (zone.IsInvalidTime(local)) local = local.AddHours(1);
        // One that falls back at midnight has 00:00 twice; the month starts at the first, which has the larger offset.
        var offset = zone.IsAmbiguousTime(local) ? zone.GetAmbiguousTimeOffsets(local).Max() : zone.GetUtcOffset(local);
        return new DateTimeOffset(local, offset).ToUniversalTime();
    }

    /// <summary>The local year and month containing <paramref name="instant"/>.</summary>
    public static (int Year, int Month) Of(DateTimeOffset instant, TimeZoneInfo zone)
    {
        var local = TimeZoneInfo.ConvertTime(instant, zone);
        return (local.Year, local.Month);
    }
}
