using FluentAssertions;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

public class StageGateTests
{
    private static GateCaseFacts Empty => new(false, false, false, false, false, 0, 0, 0, 0, false, 0);
    private static GateCaseFacts Full => new(true, true, true, true, true, 3, 1, 2, 1, true, 250);

    [Theory]
    [InlineData(GateCheckKeys.SummaryPresent)]
    [InlineData(GateCheckKeys.AffectedIndividualsCountSet)]
    [InlineData(GateCheckKeys.DataElementsSet)]
    [InlineData(GateCheckKeys.AffectedStatesSet)]
    [InlineData(GateCheckKeys.DetectionCaseIdSet)]
    [InlineData(GateCheckKeys.AtLeastOneEntity)]
    [InlineData(GateCheckKeys.AtLeastOneMaliciousEntity)]
    [InlineData(GateCheckKeys.AtLeastOneEvidence)]
    [InlineData(GateCheckKeys.AtLeastOneReport)]
    [InlineData(GateCheckKeys.IncidentCommanderAssigned)]
    public void Every_check_is_unmet_on_empty_facts_and_met_on_full_facts(string check)
    {
        GateCheckRegistry.IsSatisfied(check, Empty).Should().BeFalse();
        GateCheckRegistry.IsSatisfied(check, Full).Should().BeTrue();
    }

    [Fact]
    public void The_registry_exposes_every_built_in_check_and_ignores_unknown_keys()
    {
        GateCheckRegistry.All.Should().HaveCount(11);
        GateCheckRegistry.IsKnown(GateCheckKeys.SummaryPresent).Should().BeTrue();
        GateCheckRegistry.IsKnown("NotARealCheck").Should().BeFalse();
        // An unknown key never passes a gate and is labelled for review, rather than throwing.
        GateCheckRegistry.IsSatisfied("NotARealCheck", Full).Should().BeFalse();
        GateCheckRegistry.Label("NotARealCheck").Should().Contain("needs review");
    }

    [Fact]
    public void A_parameterized_counting_check_uses_the_supplied_threshold()
    {
        var facts = Empty with { EntityCount = 3 };
        // Default (null) behaves as the pre-stage-2 "at least one".
        GateCheckRegistry.IsSatisfied(GateCheckKeys.AtLeastOneEntity, facts, null).Should().BeTrue();
        GateCheckRegistry.IsSatisfied(GateCheckKeys.AtLeastOneEntity, facts, 3).Should().BeTrue();
        GateCheckRegistry.IsSatisfied(GateCheckKeys.AtLeastOneEntity, facts, 4).Should().BeFalse("only 3 entities");
    }

    [Fact]
    public void A_parameterized_check_labels_singular_at_one_and_plural_above()
    {
        GateCheckRegistry.Label(GateCheckKeys.AtLeastOneEntity, 1).Should().Be("At least one entity / IOC added");
        GateCheckRegistry.Label(GateCheckKeys.AtLeastOneEntity, 5).Should().Be("At least 5 entities / IOCs added");
        // Null uses the spec default (1).
        GateCheckRegistry.Label(GateCheckKeys.AtLeastOneEntity, null).Should().Be("At least one entity / IOC added");
        GateCheckRegistry.Param(GateCheckKeys.AtLeastOneEntity).Should().NotBeNull();
        GateCheckRegistry.Param(GateCheckKeys.SummaryPresent).Should().BeNull("a presence check takes no threshold");
    }

    [Fact]
    public void MinAffectedIndividuals_requires_the_recorded_count_to_reach_the_threshold()
    {
        var noCount = Empty; // HasAffectedCount == false
        var small = Empty with { HasAffectedCount = true, AffectedIndividualsCount = 100 };
        GateCheckRegistry.IsSatisfied(GateCheckKeys.MinAffectedIndividuals, noCount, 1).Should().BeFalse("no count recorded");
        GateCheckRegistry.IsSatisfied(GateCheckKeys.MinAffectedIndividuals, small, 100).Should().BeTrue();
        GateCheckRegistry.IsSatisfied(GateCheckKeys.MinAffectedIndividuals, small, 500).Should().BeFalse("below the 500 threshold");
    }

    [Fact]
    public void Malicious_entity_check_needs_a_malicious_one_not_just_any_entity()
    {
        var entitiesButNoneMalicious = Empty with { EntityCount = 4, MaliciousEntityCount = 0 };
        GateCheckRegistry.IsSatisfied(GateCheckKeys.AtLeastOneEntity, entitiesButNoneMalicious).Should().BeTrue();
        GateCheckRegistry.IsSatisfied(GateCheckKeys.AtLeastOneMaliciousEntity, entitiesButNoneMalicious).Should().BeFalse();
    }

    private static GateRequirementResult MachineReq(bool satisfied, bool blocking = true) =>
        new(Guid.NewGuid(), 0, GateRequirementKind.MachineCheck, GateCheckKeys.SummaryPresent, "check", blocking, satisfied);

    private static GateRequirementResult AttestReq(bool blocking = true) =>
        new(Guid.NewGuid(), 0, GateRequirementKind.Attestation, null, "attest", blocking, MachineSatisfied: false);

    [Fact]
    public void Only_blocking_unsatisfied_requirements_count_as_unmet()
    {
        var passingMachine = MachineReq(satisfied: true);
        var failingBlocking = MachineReq(satisfied: false);
        var failingAdvisory = MachineReq(satisfied: false, blocking: false);
        var eval = new GateEvaluation(true, StageGateTrigger.EscalateToBreach, "Breach readiness",
            new[] { passingMachine, failingBlocking, failingAdvisory });

        var unmet = eval.UnmetBlocking(new HashSet<Guid>());

        unmet.Should().ContainSingle().Which.RequirementId.Should().Be(failingBlocking.RequirementId);
        eval.IsSatisfiedBy(new HashSet<Guid>()).Should().BeFalse();
    }

    [Fact]
    public void An_attestation_is_satisfied_only_when_its_id_is_attested()
    {
        var attest = AttestReq();
        var eval = new GateEvaluation(true, StageGateTrigger.CloseCase, "Closure readiness", new[] { attest });

        eval.IsSatisfiedBy(new HashSet<Guid>()).Should().BeFalse("no attestation ticked");
        eval.IsSatisfiedBy(new HashSet<Guid> { attest.RequirementId }).Should().BeTrue("the analyst confirmed it");
    }

    [Fact]
    public void A_gate_with_all_machine_checks_passing_and_no_attestations_is_satisfied()
    {
        var eval = new GateEvaluation(true, StageGateTrigger.EscalateToIncident, "Incident readiness",
            new[] { MachineReq(true), MachineReq(true) });

        eval.IsSatisfiedBy(new HashSet<Guid>()).Should().BeTrue();
    }
}
