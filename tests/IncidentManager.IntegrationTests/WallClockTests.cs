using FluentAssertions;
using IncidentManager.Web.Components.Pages.Workspace;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-40: wall times typed in the display zone convert to UTC correctly, including around DST changes.</summary>
public class WallClockTests
{
    private static readonly TimeZoneInfo NewYork = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");

    [Fact]
    public void Resaving_a_decision_made_in_the_repeated_hour_keeps_it(/* WF-14 */)
    {
        // 2026-11-01: 01:30 happens twice in New York. The decision was at the first, 01:30 EDT (05:30Z).
        var recorded = new DateTimeOffset(2026, 11, 1, 5, 30, 0, TimeSpan.Zero);
        var draft = new CaseActionDraft
        {
            MaterialityStatus = IncidentManager.Domain.Enums.MaterialityStatus.Material,
            MaterialityDecidedOn = WallClock.ToWall(recorded, NewYork),
            MaterialityDecidedOnRecorded = recorded,
        };

        draft.DecidedOnUtc(NewYork).Should().Be(recorded, "the time wasn't changed");

        draft.MaterialityDecidedOn = new DateTime(2026, 11, 1, 9, 0, 0);
        draft.DecidedOnUtc(NewYork).Should().Be(new DateTimeOffset(2026, 11, 1, 14, 0, 0, TimeSpan.Zero), "a changed time is read as typed");
    }

    [Fact]
    public void An_ordinary_time_converts_with_the_zones_offset()
    {
        WallClock.ToUtc(new DateTime(2026, 7, 1, 9, 0, 0), NewYork)
            .Should().Be(new DateTimeOffset(2026, 7, 1, 13, 0, 0, TimeSpan.Zero));
    }

    [Fact]
    public void A_time_in_the_spring_forward_gap_lands_just_after_the_jump()
    {
        // 2026-03-08: clocks go from 02:00 EST to 03:00 EDT, so 02:30 doesn't exist. It used to be stored as 02:30Z,
        // which reads as 21:30 the evening before.
        var utc = WallClock.ToUtc(new DateTime(2026, 3, 8, 2, 30, 0), NewYork);

        utc.Should().Be(new DateTimeOffset(2026, 3, 8, 7, 30, 0, TimeSpan.Zero));
        WallClock.ToWall(utc, NewYork).Should().Be(new DateTime(2026, 3, 8, 3, 30, 0));
    }

    [Fact]
    public void A_time_in_the_fall_back_hour_converts_without_error()
    {
        // 2026-11-01 01:30 happens twice; either reading is a real instant on that day.
        var utc = WallClock.ToUtc(new DateTime(2026, 11, 1, 1, 30, 0), NewYork);
        utc.Should().BeOneOf(new DateTimeOffset(2026, 11, 1, 5, 30, 0, TimeSpan.Zero), new DateTimeOffset(2026, 11, 1, 6, 30, 0, TimeSpan.Zero));
    }
}
