using FluentAssertions;
using IncidentManager.Application.Mitre;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>HR-13: a case's techniques include what its attack chain records, not only the manual tags.</summary>
public class CaseTechniquesTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 1, 8, 0, 0, TimeSpan.Zero);

    private static Case NewCase(CaseOrigin origin = CaseOrigin.InternalDetection) => Case.Open(2026, 7, "Phish",
        "Credential phishing", Classification.Incident, Severity.High, origin, "ic1", T0);

    private static void Step(Case c, string? technique, params MitreTactic[] tactics)
    {
        var e = new TimelineEntry { CaseId = c.Id, Kind = TimelineKind.Event, OccurredAtUtc = T0, Description = "step", TechniqueId = technique, CreatedBy = "a", CreatedAtUtc = T0 };
        foreach (var t in tactics) e.Tactics.Add(new EventStepTactic { TimelineEntryId = e.Id, Tactic = t });
        c.TimelineEntries.Add(e);
    }

    [Fact]
    public void Attack_chain_techniques_join_the_tags_and_a_shared_one_is_both()
    {
        var c = NewCase();
        c.Techniques.Add(new CaseTechnique { CaseId = c.Id, TechniqueId = "T1566", Name = "Phishing", Tactic = MitreTactic.InitialAccess });
        Step(c, "T1566", MitreTactic.InitialAccess);
        Step(c, "t1078", MitreTactic.Stealth, MitreTactic.Persistence);
        Step(c, "T1078", MitreTactic.Persistence);
        Step(c, null, MitreTactic.Collection);

        var rows = CaseTechniques.For(c);

        rows.Should().HaveCount(3);
        var phishing = rows.Single(r => r.TechniqueId == "T1566");
        phishing.IsTagged.Should().BeTrue();
        phishing.ChainSteps.Should().Be(1);
        var persistence = rows.Single(r => r.TechniqueId == "T1078" && r.Tactic == MitreTactic.Persistence);
        persistence.IsTagged.Should().BeFalse();
        persistence.ChainSteps.Should().Be(2);
        persistence.Name.Should().Be("Valid Accounts", "named from the ATT&CK catalog");
    }

    [Fact]
    public void A_chain_step_without_a_tactic_merges_into_the_tag_of_the_same_technique()
    {
        var c = NewCase();
        c.Techniques.Add(new CaseTechnique { CaseId = c.Id, TechniqueId = "T1110", Name = "Brute Force", Tactic = MitreTactic.CredentialAccess });
        Step(c, "T1110");

        CaseTechniques.For(c).Should().ContainSingle().Which.ChainSteps.Should().Be(1);
    }

    [Fact]
    public void A_third_party_cases_event_steps_add_no_techniques()
    {
        var c = NewCase(CaseOrigin.ThirdParty);
        Step(c, "T1078", MitreTactic.InitialAccess);

        CaseTechniques.For(c).Should().BeEmpty();
    }
}
