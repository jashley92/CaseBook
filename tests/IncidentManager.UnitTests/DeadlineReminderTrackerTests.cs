using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Notifications;
using IncidentManager.Application.Sla;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>PROD-37: the regulatory-deadline tracker reminds once per (case, jurisdiction, band, deadline) — so a case
/// gets a reminder when it enters "at risk" and a distinct one if it crosses into "breached".</summary>
public class DeadlineReminderTrackerTests
{
    private static readonly DateTimeOffset Due = new(2026, 9, 20, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void First_sighting_of_a_band_is_new_thereafter_it_is_not()
    {
        var tracker = new DeadlineReminderTracker();
        var id = Guid.NewGuid();

        tracker.MarkNotified(id, ["NY"], SlaState.AtRisk, Due).Should().Equal("NY");
        tracker.MarkNotified(id, ["NY"], SlaState.AtRisk, Due).Should().BeEmpty();
    }

    [Fact]
    public void Crossing_from_at_risk_to_breached_is_a_fresh_reminder()
    {
        var tracker = new DeadlineReminderTracker();
        var id = Guid.NewGuid();

        tracker.MarkNotified(id, ["NY"], SlaState.AtRisk, Due).Should().Equal("NY");
        tracker.MarkNotified(id, ["NY"], SlaState.Breached, Due).Should().Equal("NY");   // new band → new episode
    }

    [Fact]
    public void Re_basing_the_deadline_is_a_fresh_reminder()
    {
        var tracker = new DeadlineReminderTracker();
        var id = Guid.NewGuid();

        tracker.MarkNotified(id, ["NY"], SlaState.AtRisk, Due).Should().Equal("NY");
        tracker.MarkNotified(id, ["NY"], SlaState.AtRisk, Due.AddHours(12)).Should().Equal("NY");  // new deadline instant
    }

    [Fact]
    public void A_second_regulator_on_the_same_clock_is_a_fresh_reminder(/* BUG-619 */)
    {
        var tracker = new DeadlineReminderTracker();
        var id = Guid.NewGuid();

        tracker.MarkNotified(id, ["NY"], SlaState.Breached, Due).Should().Equal("NY");
        tracker.MarkNotified(id, ["NY", "CA"], SlaState.Breached, Due).Should().Equal("CA");
        tracker.MarkNotified(id, ["ca", "NY"], SlaState.Breached, Due).Should().BeEmpty("a code is matched whatever its case");
    }

    [Fact]
    public void A_legacy_mark_counts_for_every_regulator_on_its_clock_once(/* BUG-619, owner decision */)
    {
        var marks = new InMemoryNotificationMarks();
        var id = Guid.NewGuid();
        marks.TryAdd(DeadlineIdentity.LegacyKey(id, SlaState.Breached, Due));   // sent by v1.6.12, no jurisdiction named
        var tracker = new DeadlineReminderTracker(marks);

        tracker.MarkNotified(id, ["NY", "NJ"], SlaState.Breached, Due).Should().BeEmpty("they were reminded before the upgrade");
        marks.TryAdd(DeadlineIdentity.LegacyKey(id, SlaState.Breached, Due)).Should().BeTrue("the legacy mark was converted");
        marks.Remove(DeadlineIdentity.LegacyKey(id, SlaState.Breached, Due));

        tracker.MarkNotified(id, ["NY", "NJ", "CA"], SlaState.Breached, Due).Should().Equal("CA");
        tracker.MarkNotified(id, ["NY"], SlaState.AtRisk, Due).Should().Equal(["NY"], "another band's legacy mark wasn't held");
    }

    [Fact]
    public void A_converted_legacy_mark_is_kept_when_the_scan_fails(/* BUG-619 */)
    {
        var marks = new InMemoryNotificationMarks();
        var id = Guid.NewGuid();
        marks.TryAdd(DeadlineIdentity.LegacyKey(id, SlaState.Breached, Due));
        var tracker = new DeadlineReminderTracker(marks);

        using (NotificationMarkBatch.Begin())   // never completed: the scan threw
            tracker.MarkNotified(id, ["NY"], SlaState.Breached, Due).Should().BeEmpty();

        tracker.MarkNotified(id, ["NY"], SlaState.Breached, Due).Should().BeEmpty("NY was reminded before the upgrade");
    }

    [Fact]
    public void Forgetting_one_regulator_leaves_the_others_marked(/* BUG-619 */)
    {
        var marks = new InMemoryNotificationMarks();
        var id = Guid.NewGuid();
        var tracker = new DeadlineReminderTracker(marks);
        tracker.MarkNotified(id, ["NY", "NJ"], SlaState.AtRisk, Due);
        marks.TryAdd("to|" + DeadlineIdentity.Key(id, "NY", SlaState.AtRisk, Due) + "|abc");
        marks.TryAdd(DeadlineIdentity.LegacyKey(id, SlaState.Breached, Due));

        tracker.ForgetJurisdiction(id, "ny");

        tracker.MarkNotified(id, ["NY", "NJ"], SlaState.AtRisk, Due).Should().Equal("NY");
        marks.TryAdd("to|" + DeadlineIdentity.Key(id, "NY", SlaState.AtRisk, Due) + "|abc").Should().BeTrue();
        tracker.MarkNotified(id, ["NY"], SlaState.Breached, Due).Should().Equal(["NY"], "a legacy mark would have held NY back");

        tracker.ForgetCase(id);
        tracker.MarkNotified(id, ["NY", "NJ"], SlaState.AtRisk, Due).Should().Equal("NY", "NJ");
    }
}
