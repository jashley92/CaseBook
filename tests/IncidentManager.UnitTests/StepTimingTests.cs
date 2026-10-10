using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// ST-01: an attack step's time as it was stated (a date, a window, on or before, not stated) and its order among
/// steps the times don't settle. Exact steps are unchanged, hash included.
/// </summary>
public class StepTimingTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Mar4 = new(2026, 3, 4, 15, 37, 0, TimeSpan.Zero);

    private static Case NewCase(CaseOrigin origin = CaseOrigin.InternalDetection) => Case.Open(
        2026, 1, "Vendor breach", "Vendor reported an intrusion",
        Classification.Incident, Severity.High, origin, "analyst1", Now);

    private static TimelineEntry Step(Case c, string what, DateTimeOffset at, StepTiming? timing = null) =>
        c.AddEventStep(at, new[] { MitreTactic.Execution }, null, null, null, what, "Vendor report", "analyst1", Now, timing: timing);

    private static List<string> Chain(Case c) =>
        c.TimelineEntries.Where(t => t.Kind == TimelineKind.Event).InTimelineOrder().Select(t => t.Description).ToList();

    [Fact]
    public void An_exact_step_stores_nothing_new_and_hashes_as_before()
    {
        var c = NewCase();
        var s = Step(c, "ran a tool", Mar4);

        s.OccurredPrecision.Should().BeNull();
        s.OccurredUntilUtc.Should().BeNull();
        s.StepOrder.Should().BeNull();
        s.OccurredAtUtc.Should().Be(Mar4);
        s.BuildCanonicalContent().Should().NotContain("|prec|").And.NotContain("|until|").And.NotContain("|ord|");
    }

    [Fact]
    public void A_stated_date_is_kept_at_noon_UTC_and_hashed()
    {
        var c = NewCase();
        var s = Step(c, "phished a user", Mar4, new StepTiming(TimePrecision.Day));

        s.OccurredAtUtc.Should().Be(new DateTimeOffset(2026, 3, 4, 12, 0, 0, TimeSpan.Zero));
        s.OccurredPrecision.Should().Be(TimePrecision.Day);
        s.IsApproximate.Should().BeTrue();
        s.BuildCanonicalContent().Should().Contain("|prec|1");
        StepTime.Stated(s).Should().Be("2026-03-04 · time not stated");
    }

    [Fact]
    public void A_window_needs_a_later_last_date()
    {
        var c = NewCase();
        var s = Step(c, "staged data", Mar4, new StepTiming(TimePrecision.Window, Mar4.AddDays(2)));
        s.OccurredUntilUtc.Should().Be(new DateTimeOffset(2026, 3, 6, 12, 0, 0, TimeSpan.Zero));
        StepTime.Stated(s).Should().Be("Between 2026-03-04 and 2026-03-06");
        StepTime.Short(s).Should().Be("2026-03-04 to 03-06");

        var bad = () => Step(c, "x", Mar4, new StepTiming(TimePrecision.Window, Mar4));
        bad.Should().Throw<ArgumentException>().WithMessage("*after its first*");
        var none = () => Step(c, "x", Mar4, new StepTiming(TimePrecision.Window));
        none.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Steps_on_the_same_date_keep_the_order_they_were_entered_and_can_be_reordered()
    {
        var c = NewCase();
        var day = new StepTiming(TimePrecision.Day);
        var a = Step(c, "A", Mar4, day);
        Step(c, "B", Mar4.AddHours(5), day);   // same date, a different hour typed: still the date
        var cc = Step(c, "C", Mar4, day);
        Chain(c).Should().Equal("A", "B", "C");

        c.MoveEventStep(cc.Id, earlier: true, "analyst1", Now);
        Chain(c).Should().Equal("A", "C", "B");
        c.MoveEventStep(a.Id, earlier: false, "analyst1", Now);
        Chain(c).Should().Equal("C", "A", "B");
    }

    [Fact]
    public void A_step_without_a_stated_time_goes_where_it_is_placed_and_follows_its_step()
    {
        var c = NewCase();
        var first = Step(c, "Initial access", Mar4);
        Step(c, "Exfiltration", Mar4.AddDays(3));
        var mid = Step(c, "Lateral movement", Now, new StepTiming(TimePrecision.NotStated, AfterStepId: first.Id));
        var lead = Step(c, "Recon", Now, new StepTiming(TimePrecision.NotStated, First: true));

        Chain(c).Should().Equal("Recon", "Initial access", "Lateral movement", "Exfiltration");
        mid.OccurredAtUtc.Should().Be(first.OccurredAtUtc);   // a sort key only
        StepTime.Stated(mid).Should().Be("Time not stated");

        // The vendor corrects the initial access time: the step placed after it moves with it; Recon (before it) doesn't.
        c.EditEventStep(first.Id, Mar4.AddDays(1), new[] { MitreTactic.InitialAccess }, null, null, null, "Initial access", null, "analyst1", Now);
        mid.OccurredAtUtc.Should().Be(Mar4.AddDays(1));
        Chain(c).Should().Equal("Recon", "Initial access", "Lateral movement", "Exfiltration");
        lead.OccurredAtUtc.Should().Be(Mar4);
    }

    [Fact]
    public void A_not_stated_step_moves_past_dated_steps_but_a_dated_step_does_not()
    {
        var c = NewCase();
        var one = Step(c, "One", Mar4);
        var two = Step(c, "Two", Mar4.AddDays(2));
        var loose = Step(c, "Loose", Now, new StepTiming(TimePrecision.NotStated, AfterStepId: two.Id));
        Chain(c).Should().Equal("One", "Two", "Loose");

        c.MoveEventStep(loose.Id, earlier: true, "analyst1", Now);
        Chain(c).Should().Equal("One", "Loose", "Two");
        c.MoveEventStep(loose.Id, earlier: true, "analyst1", Now);
        Chain(c).Should().Equal("Loose", "One", "Two");

        // Moving a dated step past a not-stated one moves the not-stated one instead.
        c.MoveEventStep(one.Id, earlier: true, "analyst1", Now);
        Chain(c).Should().Equal("One", "Loose", "Two");

        // Two dated steps: their times settle the order.
        c.MoveEventStep(loose.Id, earlier: false, "analyst1", Now);
        Chain(c).Should().Equal("One", "Two", "Loose");
        var blocked = () => c.MoveEventStep(two.Id, earlier: true, "analyst1", Now);
        blocked.Should().Throw<InvalidOperationException>().WithMessage("*correct the step's time*");
    }

    [Fact]
    public void Editing_a_dated_step_back_to_exact_clears_the_precision()
    {
        var c = NewCase();
        var s = Step(c, "A", Mar4, new StepTiming(TimePrecision.Window, Mar4.AddDays(3)));
        c.EditEventStep(s.Id, Mar4, new[] { MitreTactic.Execution }, null, null, null, "A", null, "analyst1", Now);

        s.OccurredPrecision.Should().BeNull();
        s.OccurredUntilUtc.Should().BeNull();
        s.OccurredAtUtc.Should().Be(Mar4);
    }

    [Fact]
    public void The_report_prints_the_stated_time_or_the_exact_UTC_time()
    {
        new IncidentManager.Application.Reporting.ReportAttackStep(1, Mar4, "", "", "", null, "x").When.Should().Be("2026-03-04 15:37:00Z");
        new IncidentManager.Application.Reporting.ReportAttackStep(1, Mar4, "", "", "", null, "x", Stated: "Time not stated").When
            .Should().Be("Time not stated");
    }

    [Fact]
    public void Activity_began_is_approximate_when_it_comes_from_an_approximate_first_step()
    {
        var c = NewCase();
        Step(c, "Phished", Mar4, new StepTiming(TimePrecision.Window, Mar4.AddDays(2)));
        Step(c, "Exfiltrated", Mar4.AddDays(5));
        c.OccurredAtUtc = new DateTimeOffset(2026, 3, 4, 0, 0, 0, TimeSpan.Zero);
        c.DetectedAtUtc = Mar4.AddDays(8);

        StepTime.ActivityBeganCaveat(c).Should().Be("the first attack step is between 2026-03-04 and 2026-03-06");
        var began = CaseMilestones.Project(c, MilestoneLabelsForTests()).Single(m => m.Kind == MilestoneKind.ActivityBegan);
        began.Title.Should().Be("Activity began (approximately)");
        began.Detail.Should().NotContain("before detection", "nothing is measured from an approximate time");

        // A start recorded well away from the step's dates is the analyst's own, not approximate.
        c.OccurredAtUtc = Mar4.AddDays(-20);
        StepTime.ActivityBeganCaveat(c).Should().BeNull();
    }

    private static MilestoneLabels MilestoneLabelsForTests() => new(
        x => x?.ToString() ?? "", x => x.ToString(), x => x.ToString(), x => x.ToString());
}
