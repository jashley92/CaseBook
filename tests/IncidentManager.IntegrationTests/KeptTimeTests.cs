using FluentAssertions;
using IncidentManager.Web.Components.Pages.Workspace;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-477 / BUG-503 / BUG-571 / BUG-582 (C3): a time left as shown (to the minute) keeps its recorded instant,
/// through the shared WallClock.Kept, DayValues.Kept and TransitionDraft.KeptAt.</summary>
public class KeptTimeTests
{
    private static readonly TimeZoneInfo NewYork = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");

    // 2026-11-01: 01:30 happens twice in New York. The entry was written at the first, 01:30:42 EDT (05:30:42Z).
    private static readonly DateTimeOffset Recorded = new(2026, 11, 1, 5, 30, 42, TimeSpan.Zero);

    [Fact]
    public void A_time_left_untouched_keeps_the_recorded_instant()
    {
        var shown = WallClock.ToWall(Recorded, NewYork);
        WallClock.Kept(shown, shown, Recorded, NewYork).Should().Be(Recorded);
    }

    [Fact]
    public void A_time_typed_back_to_the_minute_shown_keeps_the_recorded_instant()
    {
        var shown = WallClock.ToWall(Recorded, NewYork);   // 01:30:42, shown as 01:30
        var typed = new DateTime(2026, 11, 1, 1, 30, 0);  // the field gives back no seconds

        WallClock.Kept(typed, shown, Recorded, NewYork)
            .Should().Be(Recorded, "the field shows the same minute, so it wasn't moved an hour into standard time");
    }

    [Fact]
    public void A_changed_minute_is_read_as_typed()
    {
        var shown = WallClock.ToWall(Recorded, NewYork);
        var typed = new DateTime(2026, 11, 1, 9, 5, 0);

        WallClock.Kept(typed, shown, Recorded, NewYork)
            .Should().Be(new DateTimeOffset(2026, 11, 1, 14, 5, 0, TimeSpan.Zero));
    }

    [Fact]
    public void With_nothing_recorded_the_typed_time_is_used()
    {
        var typed = new DateTime(2026, 7, 1, 9, 0, 0);
        WallClock.Kept(typed, null, null, NewYork)
            .Should().Be(new DateTimeOffset(2026, 7, 1, 13, 0, 0, TimeSpan.Zero));
    }

    // BUG-571: the Tasks tab's edit form keeps a due left as shown.
    [Fact]
    public void A_task_due_in_the_repeated_hour_left_as_shown_keeps_its_instant()
    {
        var shown = DayValues.FromUtc(Recorded, NewYork, NewYork);   // 2026-11-01 01:30:42 (EDT)
        shown.Time.Should().NotBeNull();

        DayValues.Kept(shown.Date, shown.Time, shown, Recorded, NewYork, NewYork)
            .Should().Be(Recorded, "only another field was edited, so the due wasn't moved an hour into standard time");
        DayValues.Kept(shown.Date, new TimeOnly(1, 30), shown, Recorded, NewYork, NewYork)
            .Should().Be(Recorded, "the time typed back to the minute shown comes back without its seconds");
    }

    [Fact]
    public void A_task_due_changed_on_the_form_is_read_as_typed()
    {
        var shown = DayValues.FromUtc(Recorded, NewYork, NewYork);

        DayValues.Kept(shown.Date, new TimeOnly(9, 5), shown, Recorded, NewYork, NewYork)
            .Should().Be(new DateTimeOffset(2026, 11, 1, 14, 5, 0, TimeSpan.Zero));
        DayValues.Kept(shown.Date.AddDays(1), shown.Time, shown, Recorded, NewYork, NewYork)
            .Should().NotBe(Recorded, "a changed day is read as typed");
        DayValues.Kept(shown.Date, null, shown, Recorded, NewYork, NewYork)
            .Should().Be(DayValues.ToUtc(shown.Date, null, NewYork, NewYork), "a cleared time is the end of that day");
        DayValues.Kept(null, null, shown, Recorded, NewYork, NewYork).Should().BeNull();
    }

    [Fact]
    public void A_task_with_no_due_takes_the_typed_one()
    {
        DayValues.Kept(new DateTime(2026, 7, 1), new TimeOnly(9, 0), null, null, NewYork, NewYork)
            .Should().Be(new DateTimeOffset(2026, 7, 1, 13, 0, 0, TimeSpan.Zero));
    }

    // BUG-582: advancing from a task's offer keeps the offered instant (01:30 EDT, the first pass), though by now the
    // repeated hour has passed and 01:30 alone would read as 01:30 EST, an hour later.
    [Fact]
    public void An_offered_instant_in_the_repeated_hour_is_kept_by_the_transition()
    {
        var t = new TransitionDraft();
        t.Reset(new DateTime(2026, 11, 2, 9, 0, 0));
        t.KeptAt(Recorded, NewYork);

        t.Edited.Should().BeTrue();
        t.EffectiveUtc(NewYork).Should().Be(Recorded);
        t.When = new DateTime(2026, 11, 1, 1, 30, 0);   // typed back to the minute shown
        t.EffectiveUtc(NewYork).Should().Be(Recorded);
    }

    [Fact]
    public void A_transition_time_changed_after_an_offer_is_read_as_typed_and_Reset_forgets_the_offer()
    {
        var t = new TransitionDraft();
        t.KeptAt(Recorded, NewYork);
        t.When = new DateTime(2026, 11, 1, 9, 5, 0);
        t.EffectiveUtc(NewYork).Should().Be(new DateTimeOffset(2026, 11, 1, 14, 5, 0, TimeSpan.Zero));

        t.Reset(new DateTime(2026, 11, 1, 1, 30, 0));
        t.EffectiveUtc(NewYork).Should().BeNull("a reset draft means now");
        t.When = new DateTime(2026, 11, 1, 1, 30, 0);
        t.Edited = true;
        t.EffectiveUtc(NewYork).Should().Be(WallClock.ToUtc(new DateTime(2026, 11, 1, 1, 30, 0), NewYork), "the offer is gone");
    }

    // C3: the materiality dialog's kept decision time follows the same rule.
    [Fact]
    public void A_materiality_decision_time_left_as_shown_keeps_its_instant()
    {
        var d = new CaseActionDraft
        {
            MaterialityStatus = IncidentManager.Domain.Enums.MaterialityStatus.Material,
            MaterialityDecidedOn = new DateTime(2026, 11, 1, 1, 30, 0),
            MaterialityDecidedOnRecorded = Recorded,
        };
        d.DecidedOnUtc(NewYork).Should().Be(Recorded);
        d.MaterialityDecidedOn = new DateTime(2026, 11, 1, 1, 31, 0);
        d.DecidedOnUtc(NewYork).Should().Be(WallClock.ToUtc(new DateTime(2026, 11, 1, 1, 31, 0), NewYork));
    }
}
