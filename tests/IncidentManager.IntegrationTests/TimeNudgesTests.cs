using FluentAssertions;
using IncidentManager.Web.Components.Pages.Workspace;
using IncidentManager.Web.Components.Shared;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-480: the time nudges (-1 h, -15 min, +15 min) stop at the first and last times instead of throwing.</summary>
public sealed class TimeNudgesTests
{
    [Fact]
    public void An_ordinary_time_moves_by_the_nudge()
    {
        var at = new DateTime(2026, 10, 14, 9, 0, 0);
        TimeNudges.Shifted(at, TimeSpan.FromHours(-1)).Should().Be(new DateTime(2026, 10, 14, 8, 0, 0));
        TimeNudges.Shifted(at, TimeSpan.FromMinutes(15)).Should().Be(new DateTime(2026, 10, 14, 9, 15, 0));
    }

    [Fact]
    public void A_typed_year_one_stops_at_the_first_time()
    {
        var at = new DateTime(1, 1, 1, 0, 10, 0);
        TimeNudges.Shifted(at, TimeSpan.FromHours(-1)).Should().Be(DateTime.MinValue);
        TimeNudges.Shifted(at, TimeSpan.FromMinutes(-15)).Should().Be(DateTime.MinValue);
        TimeNudges.Shifted(DateTime.MinValue, TimeSpan.FromMinutes(-15)).Should().Be(DateTime.MinValue);
        TimeNudges.Shifted(at, TimeSpan.FromMinutes(-10)).Should().Be(DateTime.MinValue, "exactly to the edge is allowed");
        TimeNudges.Shifted(DateTime.MinValue, TimeSpan.FromMinutes(15)).Should().Be(new DateTime(1, 1, 1, 0, 15, 0));
    }

    [Fact]
    public void A_typed_year_9999_stops_at_the_last_time()
    {
        var at = new DateTime(9999, 12, 31, 23, 50, 0);
        TimeNudges.Shifted(at, TimeSpan.FromMinutes(15)).Should().Be(DateTime.MaxValue);
        TimeNudges.Shifted(DateTime.MaxValue, TimeSpan.FromMinutes(15)).Should().Be(DateTime.MaxValue);
        TimeNudges.Shifted(at, TimeSpan.FromHours(-1)).Should().Be(new DateTime(9999, 12, 31, 22, 50, 0));
    }

    [Fact]
    public void The_kind_is_kept()
    {
        TimeNudges.Shifted(DateTime.SpecifyKind(DateTime.MinValue, DateTimeKind.Unspecified), TimeSpan.FromHours(-1))
            .Kind.Should().Be(DateTimeKind.Unspecified);
    }

    [Theory]
    [InlineData("America/New_York")]
    [InlineData("Asia/Tokyo")]
    public void A_nudged_edge_time_still_converts_for_the_save(string zoneId)
    {
        // The save converts the wall time; at the edges that must not throw either (it's refused or stored as typed).
        var zone = TimeZoneInfo.FindSystemTimeZoneById(zoneId);
        var act = () =>
        {
            WallClock.ToUtc(TimeNudges.Shifted(new DateTime(1, 1, 1, 0, 10, 0), TimeSpan.FromHours(-1)), zone);
            WallClock.ToUtc(TimeNudges.Shifted(new DateTime(9999, 12, 31, 23, 50, 0), TimeSpan.FromMinutes(15)), zone);
        };
        act.Should().NotThrow();
    }
}
