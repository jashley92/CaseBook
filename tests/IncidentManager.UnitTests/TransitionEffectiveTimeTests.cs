using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>INV-05: the domain rules for dating a transition to when it happened.</summary>
public class TransitionEffectiveTimeTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 16, 8, 0, 0, TimeSpan.Zero);

    private static Case NewCase() =>
        Case.Open(2026, 1, "Phish", "Phishing", Classification.AdverseEvent, Severity.Medium,
            CaseOrigin.InternalDetection, "an1", T0);

    [Fact]
    public void Leaving_the_time_at_now_stores_no_effective_time()
    {
        var c = NewCase();
        c.ChangePhase(CasePhase.Triage, null, "an1", T0.AddHours(1), effectiveAtUtc: T0.AddHours(1));

        c.StatusChanges.Last().EffectiveAtUtc.Should().BeNull();
        c.StatusChanges.Last().EffectiveAt.Should().Be(T0.AddHours(1));
    }

    [Fact]
    public void Containment_resolution_and_closure_take_the_effective_time()
    {
        var c = NewCase();
        c.ChangePhase(CasePhase.Containment, "Isolated", "an1", T0.AddHours(8), effectiveAtUtc: T0.AddHours(2));
        c.ChangePhase(CasePhase.Recovery, "Restored", "an1", T0.AddHours(9), effectiveAtUtc: T0.AddHours(5));
        c.ChangePhase(CasePhase.Closed, "Done", "an1", T0.AddHours(10), effectiveAtUtc: T0.AddHours(9));

        c.ContainedAtUtc.Should().Be(T0.AddHours(2));
        c.ResolvedAtUtc.Should().Be(T0.AddHours(5));
        c.ClosedAtUtc.Should().Be(T0.AddHours(9));
    }

    [Fact]
    public void A_transition_cannot_be_dated_in_the_future_or_before_detection()
    {
        var c = NewCase();

        var future = () => c.ChangeSeverity(Severity.High, "x", "an1", T0.AddHours(1), effectiveAtUtc: T0.AddHours(2));
        var early = () => c.ChangeSeverity(Severity.High, "x", "an1", T0.AddHours(1), effectiveAtUtc: T0.AddHours(-1));

        future.Should().Throw<ArgumentException>().WithMessage("*future*");
        early.Should().Throw<ArgumentException>().WithMessage("*before the case was detected*");
    }

    [Fact]
    public void A_transition_cannot_be_dated_before_the_previous_change_of_the_same_kind()
    {
        var c = NewCase();
        c.ChangePhase(CasePhase.Triage, null, "an1", T0.AddHours(3), effectiveAtUtc: T0.AddHours(2));

        var act = () => c.ChangePhase(CasePhase.Containment, "Isolated", "an1", T0.AddHours(4), effectiveAtUtc: T0.AddHours(1));

        act.Should().Throw<ArgumentException>().WithMessage("*before the previous phase change*");
    }

    [Fact]
    public void The_opening_state_does_not_block_a_change_dated_before_the_case_was_filed()
    {
        // Detected at 06:00, filed in CaseBook at 08:00; escalated at 07:00 on a call, entered at 09:00.
        var c = NewCase();
        c.DetectedAtUtc = T0.AddHours(-2);

        c.Reclassify(Classification.Incident, "Agreed on the call", "ic1", T0.AddHours(1), effectiveAtUtc: T0.AddHours(-1));

        c.ClassificationChanges.Last().EffectiveAt.Should().Be(T0.AddHours(-1));
    }

    [Fact]
    public void A_milestone_is_dated_when_it_happened_and_says_when_it_was_recorded()
    {
        var c = NewCase();
        c.Reclassify(Classification.Incident, "Agreed on the call", "ic1", T0.AddHours(6), effectiveAtUtc: T0.AddHours(2));

        var m = CaseMilestones.Project(c, new MilestoneLabels(x => x?.ToString() ?? "CE", s => s.ToString(), p => p.ToString(), s => s.ToString()))
            .Single(x => x.Kind == MilestoneKind.Classification);

        m.AtUtc.Should().Be(T0.AddHours(2));
        m.RecordedAtUtc.Should().Be(T0.AddHours(6));
    }

    [Fact]
    public void Backdating_needs_a_reason_only_beyond_an_hour()
    {
        CaseService.IsBackdated(T0.AddMinutes(-59), T0).Should().BeFalse();
        CaseService.IsBackdated(T0.AddMinutes(-61), T0).Should().BeTrue();
        CaseService.IsBackdated(null, T0).Should().BeFalse();
    }
}
