using FluentAssertions;
using IncidentManager.Application.Notifications;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>E-03d: the due-soon notify-once tracker fires the first time an (item, due-date) is seen, not again.</summary>
public class DueSoonActionItemTrackerTests
{
    private static readonly DateTimeOffset Due = new(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void First_sighting_is_new_thereafter_it_is_not()
    {
        var tracker = new DueSoonActionItemTracker();
        var id = Guid.NewGuid();

        tracker.TryMarkNotified(id, Due).Should().BeTrue();
        tracker.TryMarkNotified(id, Due).Should().BeFalse();
    }

    [Fact]
    public void Rescheduling_to_a_new_due_date_is_a_fresh_reminder()
    {
        var tracker = new DueSoonActionItemTracker();
        var id = Guid.NewGuid();

        tracker.TryMarkNotified(id, Due).Should().BeTrue();
        tracker.TryMarkNotified(id, Due.AddDays(7)).Should().BeTrue();   // new due date → new episode
    }
}
