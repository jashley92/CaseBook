using FluentAssertions;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

public class NotificationDeadlineTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 8, 12, 0, 0, TimeSpan.Zero);

    private static NotificationRuleSet Rules(int defaultWindow, params (string Code, string Label, int Hours)[] rules)
    {
        var map = rules.ToDictionary(r => r.Code, r => (r.Label, r.Hours), StringComparer.OrdinalIgnoreCase);
        return new NotificationRuleSet(map, defaultWindow);
    }

    [Fact]
    public void No_start_instant_means_no_countdown()
    {
        var result = NotificationDeadlinePolicy.Evaluate(
            startInstant: null, reportedAtUtc: null, jurisdictionCodes: new[] { "NY" },
            Rules(72, ("NY", "New York", 72)), 80, Now);
        result.Should().BeEmpty();
    }

    [Theory]
    [InlineData(10, SlaState.OnTrack)]   // 10h of 72 elapsed
    [InlineData(60, SlaState.AtRisk)]    // 60/72 = 83% > 80% threshold
    [InlineData(80, SlaState.Breached)]  // past the 72h window
    public void An_open_clock_moves_through_on_track_at_risk_and_breached(int elapsedHours, SlaState expected)
    {
        var start = Now.AddHours(-elapsedHours);
        var s = NotificationDeadlinePolicy.Evaluate(start, null, new[] { "NY" },
            Rules(72, ("NY", "New York", 72)), 80, Now).Should().ContainSingle().Subject;
        s.State.Should().Be(expected);
        s.JurisdictionLabel.Should().Be("New York");
        s.DueAtUtc.Should().Be(start.AddHours(72));
    }

    [Fact]
    public void Reporting_before_the_deadline_is_met_and_after_is_missed()
    {
        var start = Now.AddHours(-100);
        var met = NotificationDeadlinePolicy.Evaluate(start, start.AddHours(48), new[] { "NY" },
            Rules(72, ("NY", "New York", 72)), 80, Now).Single();
        met.State.Should().Be(SlaState.Met);

        var missed = NotificationDeadlinePolicy.Evaluate(start, start.AddHours(96), new[] { "NY" },
            Rules(72, ("NY", "New York", 72)), 80, Now).Single();
        missed.State.Should().Be(SlaState.Missed);
    }

    [Fact]
    public void A_jurisdiction_without_a_rule_falls_back_to_the_default_window()
    {
        var start = Now.AddHours(-1);
        var s = NotificationDeadlinePolicy.Evaluate(start, null, new[] { "CT" },
            Rules(48, ("NY", "New York", 72)), 80, Now).Single();
        s.WindowHours.Should().Be(48);
        s.DueAtUtc.Should().Be(start.AddHours(48));
        s.JurisdictionLabel.Should().Be("CT"); // labelled by the bare code when no rule names it
    }

    [Fact]
    public void The_headline_is_the_soonest_due_open_clock()
    {
        var start = Now.AddHours(-1);
        var statuses = NotificationDeadlinePolicy.Evaluate(start, null, new[] { "NY", "US" },
            Rules(72, ("NY", "New York", 24), ("US", "Federal", 72)), 80, Now);
        var headline = NotificationDeadlinePolicy.Headline(statuses);
        headline!.JurisdictionCode.Should().Be("NY"); // 24h window is due before the 72h one
    }

    [Fact]
    public void Determination_basis_starts_only_when_the_case_is_material()
    {
        var decided = Now.AddHours(-5);

        NotificationDeadlineService.ResolveStart(NotificationStartBasis.Determination, Classification.Breach,
            Now.AddHours(-50), MaterialityStatus.Material, decided, Now).Should().Be(decided);

        NotificationDeadlineService.ResolveStart(NotificationStartBasis.Determination, Classification.Breach,
            Now.AddHours(-50), MaterialityStatus.UnderReview, null, null).Should().BeNull();

        NotificationDeadlineService.ResolveStart(NotificationStartBasis.Determination, Classification.Breach,
            Now.AddHours(-50), MaterialityStatus.NotMaterial, decided, Now).Should().BeNull();
    }

    [Fact]
    public void Detection_basis_starts_from_detection_only_for_a_breach()
    {
        var detected = Now.AddHours(-50);

        NotificationDeadlineService.ResolveStart(NotificationStartBasis.Detection, Classification.Breach,
            detected, MaterialityStatus.Undetermined, null, null).Should().Be(detected);

        NotificationDeadlineService.ResolveStart(NotificationStartBasis.Detection, Classification.Incident,
            detected, MaterialityStatus.Material, Now, Now).Should().BeNull();
    }
}
