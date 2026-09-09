using FluentAssertions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

public class SlaPolicyTests
{
    private static readonly DateTimeOffset Detected = new(2026, 8, 1, 0, 0, 0, TimeSpan.Zero);

    // Critical: 4h to contain, 24h to resolve; at-risk at 80%.
    private static SlaTargets Targets(int atRiskPct = 80) => new(
        new Dictionary<(SlaClock, Severity), int>
        {
            [(SlaClock.Containment, Severity.Critical)] = 4,
            [(SlaClock.Resolution, Severity.Critical)] = 24,
        },
        atRiskPct);

    private static SlaStatus Head(DateTimeOffset now, DateTimeOffset? contained = null,
        DateTimeOffset? resolved = null, CasePhase phase = CasePhase.Triage, Severity sev = Severity.Critical)
        => SlaPolicy.Evaluate(sev, phase, Detected, contained, resolved, Targets(), now);

    [Fact]
    public void Informational_has_no_sla()
    {
        var status = Head(Detected.AddHours(100), sev: Severity.Informational);
        status.State.Should().Be(SlaState.NoTarget);
    }

    [Fact]
    public void Without_a_detection_stamp_there_is_no_sla()
    {
        var status = SlaPolicy.Evaluate(Severity.Critical, CasePhase.Triage,
            detectedAtUtc: null, containedAtUtc: null, resolvedAtUtc: null, Targets(), Detected.AddHours(10));
        status.State.Should().Be(SlaState.NoTarget);
    }

    [Fact]
    public void An_open_case_inside_the_threshold_is_on_track()
    {
        // 2h of a 4h target elapsed → below the 80% (3.2h) at-risk mark.
        var status = Head(Detected.AddHours(2));
        status.State.Should().Be(SlaState.OnTrack);
        status.Clock.Should().Be(SlaClock.Containment);
        status.TargetHours.Should().Be(4);
        status.DueAtUtc.Should().Be(Detected.AddHours(4));
        status.Remaining.Should().Be(TimeSpan.FromHours(2));
    }

    [Fact]
    public void An_open_case_past_the_threshold_is_at_risk()
    {
        // 3.5h of 4h elapsed → past the 3.2h at-risk mark, before the 4h due.
        var status = Head(Detected.AddHours(3.5));
        status.State.Should().Be(SlaState.AtRisk);
        status.NeedsAttention.Should().BeTrue();
        status.Remaining!.Value.Should().BeLessThan(TimeSpan.FromHours(1));
    }

    [Fact]
    public void An_open_case_past_target_without_containment_is_breached()
    {
        var status = Head(Detected.AddHours(6));
        status.State.Should().Be(SlaState.Breached);
        status.NeedsAttention.Should().BeTrue();
        status.Remaining!.Value.Should().BeNegative();
    }

    [Fact]
    public void Contained_within_target_is_met()
    {
        // Contained at 3h (< 4h). Not yet resolved but case fully progressed → historical containment.
        var status = SlaPolicy.Evaluate(Severity.Critical, CasePhase.Closed, Detected,
            containedAtUtc: Detected.AddHours(3), resolvedAtUtc: Detected.AddHours(10), Targets(), Detected.AddHours(50));
        // Closed + resolved within 24h → the headline is the resolution outcome (Met).
        status.State.Should().Be(SlaState.Met);
        status.Clock.Should().Be(SlaClock.Resolution);
    }

    [Fact]
    public void Containment_after_target_is_missed()
    {
        var (containment, _) = SlaPolicy.Breakdown(Severity.Critical, CasePhase.Containment, Detected,
            containedAtUtc: Detected.AddHours(9), resolvedAtUtc: null, Targets(), Detected.AddHours(9));
        containment.State.Should().Be(SlaState.Missed);
        containment.ElapsedHours.Should().Be(9);
    }

    [Fact]
    public void Once_contained_the_active_clock_moves_to_resolution()
    {
        // Contained on time at 3h; now at 10h, not yet resolved, case still open → resolution clock is active.
        var status = Head(Detected.AddHours(10), contained: Detected.AddHours(3), phase: CasePhase.Eradication);
        status.Clock.Should().Be(SlaClock.Resolution);
        status.IsActive.Should().BeTrue();
        status.State.Should().Be(SlaState.OnTrack); // 10h of 24h, below the 19.2h at-risk mark
    }

    [Fact]
    public void Resolution_clock_flags_at_risk_near_its_target()
    {
        // 20h of a 24h resolution target = 83% > 80% → at risk.
        var status = Head(Detected.AddHours(20), contained: Detected.AddHours(3), phase: CasePhase.Eradication);
        status.Clock.Should().Be(SlaClock.Resolution);
        status.State.Should().Be(SlaState.AtRisk);
    }

    [Fact]
    public void A_severity_with_no_configured_target_has_no_sla()
    {
        // High is absent from the target set entirely.
        var status = SlaPolicy.Evaluate(Severity.High, CasePhase.Triage, Detected, null, null,
            Targets(), Detected.AddHours(100));
        status.State.Should().Be(SlaState.NoTarget);
    }

    [Fact]
    public void A_closed_case_that_never_reached_a_milestone_is_not_chased()
    {
        var status = SlaPolicy.Evaluate(Severity.Critical, CasePhase.Closed, Detected,
            containedAtUtc: null, resolvedAtUtc: null, Targets(), Detected.AddHours(500));
        status.State.Should().Be(SlaState.NoTarget);
    }

    [Fact]
    public void Breakdown_reports_both_clocks_independently()
    {
        var (containment, resolution) = SlaPolicy.Breakdown(Severity.Critical, CasePhase.Eradication,
            Detected, containedAtUtc: Detected.AddHours(3), resolvedAtUtc: null, Targets(), Detected.AddHours(10));
        containment.State.Should().Be(SlaState.Met);          // 3h < 4h
        resolution.State.Should().Be(SlaState.OnTrack);        // 10h of 24h, active
    }

    [Fact]
    public void HoursFor_treats_zero_or_absent_as_no_target()
    {
        var targets = new SlaTargets(new Dictionary<(SlaClock, Severity), int>
        {
            [(SlaClock.Containment, Severity.Low)] = 0,
        }, 80);
        targets.HoursFor(SlaClock.Containment, Severity.Low).Should().BeNull();
        targets.HoursFor(SlaClock.Containment, Severity.High).Should().BeNull();
    }

    [Fact]
    public void The_administered_sla_settings_exist_with_the_right_shape()
    {
        foreach (var key in new[]
                 {
                     "Sla:Containment:Critical", "Sla:Containment:High", "Sla:Containment:Medium", "Sla:Containment:Low",
                     "Sla:Resolution:Critical", "Sla:Resolution:High", "Sla:Resolution:Medium", "Sla:Resolution:Low",
                     "Sla:AtRiskThresholdPercent",
                 })
        {
            SettingsCatalog.IsEditable(key).Should().BeTrue($"{key} should be administrable");
            SettingsCatalog.ByKey[key].Kind.Should().Be(SettingKind.Int);
            SettingsCatalog.ByKey[key].Group.Should().Be("Response SLA");
        }

        SettingsCatalog.ByKey["Sla:Containment:Critical"].Default.Should().Be("4");
        SettingsCatalog.ByKey["Sla:AtRiskThresholdPercent"].Default.Should().Be("80");
    }
}
