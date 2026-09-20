using FluentAssertions;
using IncidentManager.Application.Notifications;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>PROD-38: the stale-case tracker nudges once per quiet spell — keyed on the last-activity instant,
/// so any new activity (a later instant) re-arms the nudge.</summary>
public class StaleCaseTrackerTests
{
    private static readonly DateTimeOffset LastActivity = new(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void First_sighting_of_a_quiet_spell_is_new_thereafter_it_is_not()
    {
        var tracker = new StaleCaseTracker();
        var id = Guid.NewGuid();

        tracker.TryMarkNotified(id, LastActivity).Should().BeTrue();
        tracker.TryMarkNotified(id, LastActivity).Should().BeFalse();
    }

    [Fact]
    public void New_activity_re_arms_the_nudge()
    {
        var tracker = new StaleCaseTracker();
        var id = Guid.NewGuid();

        tracker.TryMarkNotified(id, LastActivity).Should().BeTrue();
        tracker.TryMarkNotified(id, LastActivity.AddHours(1)).Should().BeTrue();   // later activity → fresh spell
    }
}
