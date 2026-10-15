using FluentAssertions;
using IncidentManager.Web.Components.Pages.CaseTabs;
using IncidentManager.Web.Components.Pages.Workspace;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-477 / BUG-503: an edited entry's time left as shown (to the minute) keeps its recorded instant.</summary>
public class KeptTimeTests
{
    private static readonly TimeZoneInfo NewYork = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");

    // 2026-11-01: 01:30 happens twice in New York. The entry was written at the first, 01:30:42 EDT (05:30:42Z).
    private static readonly DateTimeOffset Recorded = new(2026, 11, 1, 5, 30, 42, TimeSpan.Zero);

    [Fact]
    public void A_time_left_untouched_keeps_the_recorded_instant()
    {
        var shown = WallClock.ToWall(Recorded, NewYork);
        CaseTimelineTab.KeptOrTypedUtc(shown, shown, Recorded, NewYork).Should().Be(Recorded);
    }

    [Fact]
    public void A_time_typed_back_to_the_minute_shown_keeps_the_recorded_instant()
    {
        var shown = WallClock.ToWall(Recorded, NewYork);   // 01:30:42, shown as 01:30
        var typed = new DateTime(2026, 11, 1, 1, 30, 0);  // the field gives back no seconds

        CaseTimelineTab.KeptOrTypedUtc(typed, shown, Recorded, NewYork)
            .Should().Be(Recorded, "the field shows the same minute, so it wasn't moved an hour into standard time");
    }

    [Fact]
    public void A_changed_minute_is_read_as_typed()
    {
        var shown = WallClock.ToWall(Recorded, NewYork);
        var typed = new DateTime(2026, 11, 1, 9, 5, 0);

        CaseTimelineTab.KeptOrTypedUtc(typed, shown, Recorded, NewYork)
            .Should().Be(new DateTimeOffset(2026, 11, 1, 14, 5, 0, TimeSpan.Zero));
    }

    [Fact]
    public void With_nothing_recorded_the_typed_time_is_used()
    {
        var typed = new DateTime(2026, 7, 1, 9, 0, 0);
        CaseTimelineTab.KeptOrTypedUtc(typed, null, null, NewYork)
            .Should().Be(new DateTimeOffset(2026, 7, 1, 13, 0, 0, TimeSpan.Zero));
    }
}
