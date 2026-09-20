using FluentAssertions;
using IncidentManager.Application.Notifications;
using IncidentManager.Application.Sla;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>PROD-37: the regulatory-deadline tracker reminds once per (case, band, deadline) — so a case
/// gets a reminder when it enters "at risk" and a distinct one if it crosses into "breached".</summary>
public class DeadlineReminderTrackerTests
{
    private static readonly DateTimeOffset Due = new(2026, 9, 20, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void First_sighting_of_a_band_is_new_thereafter_it_is_not()
    {
        var tracker = new DeadlineReminderTracker();
        var id = Guid.NewGuid();

        tracker.TryMarkNotified(id, SlaState.AtRisk, Due).Should().BeTrue();
        tracker.TryMarkNotified(id, SlaState.AtRisk, Due).Should().BeFalse();
    }

    [Fact]
    public void Crossing_from_at_risk_to_breached_is_a_fresh_reminder()
    {
        var tracker = new DeadlineReminderTracker();
        var id = Guid.NewGuid();

        tracker.TryMarkNotified(id, SlaState.AtRisk, Due).Should().BeTrue();
        tracker.TryMarkNotified(id, SlaState.Breached, Due).Should().BeTrue();   // new band → new episode
    }

    [Fact]
    public void Re_basing_the_deadline_is_a_fresh_reminder()
    {
        var tracker = new DeadlineReminderTracker();
        var id = Guid.NewGuid();

        tracker.TryMarkNotified(id, SlaState.AtRisk, Due).Should().BeTrue();
        tracker.TryMarkNotified(id, SlaState.AtRisk, Due.AddHours(12)).Should().BeTrue();  // new deadline instant
    }
}
