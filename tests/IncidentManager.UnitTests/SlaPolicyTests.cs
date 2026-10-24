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

    // ---- PROD-08: detection clock + Breach overrides ----

    private static SlaTargets WithDetectionAndBreach() => new(
        new Dictionary<(SlaClock, Severity), int>
        {
            [(SlaClock.Containment, Severity.Critical)] = 4,
            [(SlaClock.Resolution, Severity.Critical)] = 24,
            [(SlaClock.Detection, Severity.Critical)] = 24,
        },
        80,
        new Dictionary<(SlaClock, Severity), int> { [(SlaClock.Containment, Severity.Critical)] = 2 });

    [Fact]
    public void Detection_is_a_historical_outcome_from_occurred_to_detected()
    {
        var t = WithDetectionAndBreach();
        var met = SlaPolicy.EvaluateDetection(Severity.Critical, Detected.AddHours(-10), Detected, t);
        met.State.Should().Be(SlaState.Met);
        met.Clock.Should().Be(SlaClock.Detection);
        met.ElapsedHours.Should().Be(10);
        met.IsActive.Should().BeFalse();

        SlaPolicy.EvaluateDetection(Severity.Critical, Detected.AddHours(-30), Detected, t).State.Should().Be(SlaState.Missed);
    }

    [Fact]
    public void Detection_needs_an_occurred_time_and_a_target()
    {
        var t = WithDetectionAndBreach();
        SlaPolicy.EvaluateDetection(Severity.Critical, null, Detected, t).State.Should().Be(SlaState.NoTarget);
        SlaPolicy.EvaluateDetection(Severity.High, Detected.AddHours(-1), Detected, t).State.Should().Be(SlaState.NoTarget);
        SlaPolicy.EvaluateDetection(Severity.Critical, Detected.AddHours(-1), Detected, Targets()).State.Should().Be(SlaState.NoTarget);
        SettingsCatalog.ByKey["Sla:Detection:Critical"].Default.Should().BeNull("detection targets are opt-in");
    }

    [Fact]
    public void Breach_cases_use_their_override_and_others_the_general_target()
    {
        var t = WithDetectionAndBreach();
        var now = Detected.AddHours(3);

        // 3h in: inside the general 4h containment target, past the Breach-only 2h override.
        SlaPolicy.Evaluate(Severity.Critical, CasePhase.Containment, Detected, null, null, t, now, Classification.Incident)
            .State.Should().Be(SlaState.OnTrack);
        var breach = SlaPolicy.Evaluate(Severity.Critical, CasePhase.Containment, Detected, null, null, t, now, Classification.Breach);
        breach.State.Should().Be(SlaState.Breached);
        breach.TargetHours.Should().Be(2);

        // No Breach override for resolution → the general 24h applies.
        t.HoursFor(SlaClock.Resolution, Severity.Critical, Classification.Breach).Should().Be(24);
        SettingsCatalog.ByKey["Sla:Breach:Containment:Critical"].Default.Should().BeNull();
    }

    // Third-party targets as settings give them: containment 8h, resolution none, the vendor's notice 72h; High unset.
    private static SlaTargets WithThirdParty() => SlaTargetSettings.From(key => key switch
    {
        "Sla:Containment:Critical" => "4",
        "Sla:Resolution:Critical" => "24",
        "Sla:Detection:Critical" => "24",
        "Sla:Containment:High" => "12",
        "Sla:Breach:Containment:Critical" => "2",
        "Sla:ThirdParty:Containment:Critical" => "8",
        "Sla:ThirdParty:Resolution:Critical" => "None",
        "Sla:ThirdParty:Detection:Critical" => "72",
        "Sla:ThirdParty:Containment:High" => "",
        _ => null
    });

    [Fact]
    public void Third_party_events_use_their_own_targets_and_none_turns_a_clock_off()
    {
        var t = WithThirdParty();
        var now = Detected.AddHours(6);

        // 6h in: past the general 4h containment target, inside the third-party 8h one.
        SlaPolicy.Evaluate(Severity.Critical, CasePhase.Containment, Detected, null, null, t, now, Classification.Incident)
            .State.Should().Be(SlaState.Breached);
        var vendor = SlaPolicy.Breakdown(Severity.Critical, CasePhase.Containment, Detected, null, null, t, now,
            Classification.Incident, origin: CaseOrigin.ThirdParty);
        (vendor.Containment.State, vendor.Containment.TargetHours).Should().Be((SlaState.OnTrack, 8));
        // Resolution is none for third-party events: no clock at all, not the general 24h.
        vendor.Resolution.State.Should().Be(SlaState.NoTarget);

        // Blank uses the general target.
        t.HoursFor(SlaClock.Containment, Severity.High, origin: CaseOrigin.ThirdParty).Should().Be(12);
    }

    [Fact]
    public void A_breach_override_comes_before_the_third_party_one()
    {
        var t = WithThirdParty();
        t.HoursFor(SlaClock.Containment, Severity.Critical, Classification.Breach, CaseOrigin.ThirdParty).Should().Be(2);
        // No breach override for resolution: the third-party none applies.
        t.HoursFor(SlaClock.Resolution, Severity.Critical, Classification.Breach, CaseOrigin.ThirdParty).Should().BeNull();
    }

    [Fact]
    public void A_third_party_events_detection_clock_is_the_vendors_notice()
    {
        var t = WithThirdParty();
        // Told 48h after the vendor's incident began: missed against our own 24h, met against the 72h notice term.
        SlaPolicy.EvaluateDetection(Severity.Critical, Detected.AddHours(-48), Detected, t).State.Should().Be(SlaState.Missed);
        var notice = SlaPolicy.EvaluateDetection(Severity.Critical, Detected.AddHours(-48), Detected, t, CaseOrigin.ThirdParty);
        (notice.State, notice.TargetHours).Should().Be((SlaState.Met, 72));
    }

    [Fact]
    public void Only_a_third_party_target_can_be_saved_as_none()
    {
        SettingsCatalog.Normalize(SettingsCatalog.ByKey["Sla:ThirdParty:Resolution:Low"], " NONE ").Should().Be("none");
        SettingsCatalog.Normalize(SettingsCatalog.ByKey["Sla:ThirdParty:Resolution:Low"], "36").Should().Be("36");
        SettingsCatalog.Normalize(SettingsCatalog.ByKey["Sla:ThirdParty:Resolution:Low"], "").Should().BeNull();
        var general = () => SettingsCatalog.Normalize(SettingsCatalog.ByKey["Sla:Resolution:Low"], "none");
        general.Should().Throw<ArgumentException>();
        var breach = () => SettingsCatalog.Normalize(SettingsCatalog.ByKey["Sla:Breach:Resolution:Low"], "none");
        breach.Should().Throw<ArgumentException>();
    }
}
