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

    // --- INV-05b: correcting when a recorded transition happened ---

    [Fact]
    public void Correcting_a_phase_change_moves_its_milestone_and_keeps_the_recorded_time()
    {
        var c = NewCase();
        c.ChangePhase(CasePhase.Containment, "Isolated", "an1", T0.AddHours(6));
        var change = c.StatusChanges.Last();

        var k = c.CorrectTransitionTime(TransitionKind.Phase, change.Id, T0.AddHours(2), "Isolated on the call", "ic1", T0.AddHours(8));

        change.EffectiveAt.Should().Be(T0.AddHours(2));
        change.ChangedAtUtc.Should().Be(T0.AddHours(6));
        c.ContainedAtUtc.Should().Be(T0.AddHours(2));
        k.FromEffectiveUtc.Should().Be(T0.AddHours(6));
        k.ToEffectiveUtc.Should().Be(T0.AddHours(2));
        c.TimeCorrections.Should().ContainSingle();
    }

    [Fact]
    public void A_correction_stays_in_order_with_the_changes_before_and_after_it()
    {
        var c = NewCase();
        c.ChangePhase(CasePhase.Triage, null, "an1", T0.AddHours(1));
        c.ChangePhase(CasePhase.Containment, null, "an1", T0.AddHours(3));
        c.ChangePhase(CasePhase.Eradication, null, "an1", T0.AddHours(5));
        var containment = c.StatusChanges.Single(x => x.To == CasePhase.Containment);

        var tooEarly = () => c.CorrectTransitionTime(TransitionKind.Phase, containment.Id, T0.AddMinutes(30), "x", "ic1", T0.AddHours(6));
        var tooLate = () => c.CorrectTransitionTime(TransitionKind.Phase, containment.Id, T0.AddHours(5.5), "x", "ic1", T0.AddHours(6));

        tooEarly.Should().Throw<ArgumentException>().WithMessage("*made before it*");
        tooLate.Should().Throw<ArgumentException>().WithMessage("*made after it*");
        c.TimeCorrections.Should().BeEmpty();
    }

    [Fact]
    public void A_correction_needs_a_reason_and_the_opening_state_cannot_be_redated()
    {
        var c = NewCase();
        c.ChangeSeverity(Severity.High, "Scope grew", "an1", T0.AddHours(2));
        var opening = c.SeverityChanges.Single(x => x.From is null);
        var change = c.SeverityChanges.Single(x => x.From is not null);

        var noReason = () => c.CorrectTransitionTime(TransitionKind.Severity, change.Id, T0.AddHours(1), " ", "an1", T0.AddHours(3));
        var openingState = () => c.CorrectTransitionTime(TransitionKind.Severity, opening.Id, T0.AddHours(1), "x", "an1", T0.AddHours(3));

        noReason.Should().Throw<ArgumentException>().WithMessage("*reason*");
        openingState.Should().Throw<InvalidOperationException>().WithMessage("*opening state*");
    }

    [Fact]
    public void A_corrected_milestone_offers_its_transition_for_correction()
    {
        var c = NewCase();
        c.Reclassify(Classification.Incident, "Confirmed", "ic1", T0.AddHours(3));
        var change = c.ClassificationChanges.Last();
        c.CorrectTransitionTime(TransitionKind.Classification, change.Id, T0.AddHours(1), "Agreed on the call", "ic1", T0.AddHours(4));

        var m = CaseMilestones.Project(c, new MilestoneLabels(x => x?.ToString() ?? "CE", s => s.ToString(), p => p.ToString(), s => s.ToString()))
            .Single(x => x.Kind == MilestoneKind.Classification);

        m.AtUtc.Should().Be(T0.AddHours(1));
        m.RecordedAtUtc.Should().Be(T0.AddHours(3));
        m.Transition.Should().Be((TransitionKind.Classification, change.Id));
    }

    [Fact]
    public void Backdating_needs_a_reason_only_beyond_an_hour()
    {
        CaseService.IsBackdated(T0.AddMinutes(-59), T0).Should().BeFalse();
        CaseService.IsBackdated(T0.AddMinutes(-61), T0).Should().BeTrue();
        CaseService.IsBackdated(null, T0).Should().BeFalse();
    }
}
