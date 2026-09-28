using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Dashboards;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>Calendar months and quarters in the reporting time zone, including daylight-saving edges.</summary>
public class ZonedMonthsTests
{
    private static readonly TimeZoneInfo Eastern = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");

    // A zone that changes its clocks at midnight on the 1st: springs forward 00:00 → 01:00 on 1 April and falls back
    // 01:00 → 00:00 on 1 October. None of the listed zones does this today; the rules must hold if one is added.
    private static readonly TimeZoneInfo MidnightShift = TimeZoneInfo.CreateCustomTimeZone("Test/MidnightShift",
        TimeSpan.FromHours(-3), "Midnight shift", "Standard", "Daylight",
        [TimeZoneInfo.AdjustmentRule.CreateAdjustmentRule(new DateTime(2000, 1, 1), new DateTime(2099, 12, 31), TimeSpan.FromHours(1),
            TimeZoneInfo.TransitionTime.CreateFixedDateRule(new DateTime(1, 1, 1, 0, 0, 0), 4, 1),
            TimeZoneInfo.TransitionTime.CreateFixedDateRule(new DateTime(1, 1, 1, 1, 0, 0), 10, 1))]);

    private static DateTimeOffset Utc(int y, int m, int d, int h, int min = 0) => new(y, m, d, h, min, 0, TimeSpan.Zero);

    [Fact]
    public void Eastern_months_start_at_local_midnight_in_standard_and_daylight_time()
    {
        ZonedMonths.StartUtc(2026, 1, Eastern).Should().Be(Utc(2026, 1, 1, 5));   // EST, UTC-5
        ZonedMonths.StartUtc(2026, 7, Eastern).Should().Be(Utc(2026, 7, 1, 4));   // EDT, UTC-4
    }

    [Fact]
    public void The_year_rolls_over_at_local_midnight()
    {
        // 03:00 UTC on 1 January 2026 is 22:00 on 31 December 2025 in New York.
        ZonedMonths.Of(Utc(2026, 1, 1, 3), Eastern).Should().Be((2025, 12));
        ZonedMonths.Of(Utc(2026, 1, 1, 5), Eastern).Should().Be((2026, 1));
        ProgramPeriod.Containing(Utc(2026, 1, 1, 3), Eastern).Should().Be(new ProgramPeriod(2025, 4));
        new ProgramPeriod(2026, 1).Previous.Should().Be(new ProgramPeriod(2025, 4));
        new ProgramPeriod(2025, 4).EndUtc(Eastern).Should().Be(Utc(2026, 1, 1, 5));
    }

    [Fact]
    public void A_month_with_no_local_midnight_starts_when_the_clock_resumes()
    {
        // 00:00 on 1 April doesn't exist; the day begins at 01:00 daylight (UTC-2), the instant after 23:59:59 standard.
        ZonedMonths.StartUtc(2026, 4, MidnightShift).Should().Be(Utc(2026, 4, 1, 3));
        ZonedMonths.Of(Utc(2026, 4, 1, 2, 59), MidnightShift).Should().Be((2026, 3));
        ZonedMonths.Of(Utc(2026, 4, 1, 3), MidnightShift).Should().Be((2026, 4));
    }

    [Fact]
    public void A_month_whose_midnight_happens_twice_starts_at_the_first()
    {
        // 00:00 on 1 October occurs at 02:00 UTC (daylight) and again at 03:00 UTC (standard); October starts at the first.
        ZonedMonths.StartUtc(2026, 10, MidnightShift).Should().Be(Utc(2026, 10, 1, 2));
        ZonedMonths.Of(Utc(2026, 10, 1, 1, 59), MidnightShift).Should().Be((2026, 9));
    }
}
