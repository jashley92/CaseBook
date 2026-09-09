using FluentAssertions;
using IncidentManager.Application.Mitre;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

public class AttackCatalogTests
{
    [Fact]
    public void Loads_the_embedded_v19_catalogue()
    {
        AttackCatalog.Version.Should().Be("v19.1");
        AttackCatalog.All.Length.Should().BeGreaterThan(600);
        AttackCatalog.All.Should().Contain(t => t.IsSubtechnique);
        AttackCatalog.All.Should().Contain(t => !t.IsSubtechnique);
    }

    [Fact]
    public void Every_technique_has_at_least_one_real_tactic()
    {
        // The generator maps every kill-chain phase to a tactic; nothing should land on Unspecified.
        AttackCatalog.All.Should().OnlyContain(t => t.Tactics.Count > 0);
        AttackCatalog.All.SelectMany(t => t.Tactics).Should().NotContain(MitreTactic.Unspecified);
    }

    [Fact]
    public void Find_is_exact_and_case_insensitive()
    {
        var upper = AttackCatalog.Find("T1566");
        var lower = AttackCatalog.Find("t1566");

        upper.Should().NotBeNull();
        upper!.Name.Should().Be("Phishing");
        upper.IsSubtechnique.Should().BeFalse();
        upper.PrimaryTactic.Should().Be(MitreTactic.InitialAccess);
        lower.Should().BeSameAs(upper);

        AttackCatalog.Find("T9999").Should().BeNull();
        AttackCatalog.Find("  ").Should().BeNull();
        AttackCatalog.Find(null).Should().BeNull();
    }

    [Fact]
    public void Subtechnique_carries_its_parent_id()
    {
        var sub = AttackCatalog.Find("T1566.001");
        sub.Should().NotBeNull();
        sub!.IsSubtechnique.Should().BeTrue();
        sub.ParentId.Should().Be("T1566");
        sub.Name.Should().Be("Spearphishing Attachment");
    }

    [Fact]
    public void Carries_the_v19_tactic_split()
    {
        // v19 renamed Defense Evasion -> Stealth (TA0005) and added Defense Impairment (TA0112).
        AttackCatalog.Find("T1055.011")!.Tactics.Should().Contain(MitreTactic.Stealth);
        AttackCatalog.Find("T1112")!.Tactics.Should().Contain(MitreTactic.DefenseImpairment);
    }

    [Fact]
    public void Search_by_id_prefix_ranks_the_exact_id_first()
    {
        var hits = AttackCatalog.Search("T1566", limit: 10);
        hits.Should().NotBeEmpty();
        hits[0].Id.Should().Be("T1566");
        hits.Should().Contain(t => t.Id == "T1566.001");
    }

    [Fact]
    public void Search_by_name_substring_finds_the_technique()
    {
        var hits = AttackCatalog.Search("spearphishing", limit: 20);
        hits.Should().Contain(t => t.Id == "T1566.001");
    }

    [Fact]
    public void Empty_search_returns_top_level_techniques_only()
    {
        var hits = AttackCatalog.Search("", limit: 15);
        hits.Should().NotBeEmpty();
        hits.Should().OnlyContain(t => !t.IsSubtechnique);
    }

    [Fact]
    public void Search_respects_the_limit_and_a_zero_limit_returns_nothing()
    {
        AttackCatalog.Search("T1", limit: 5).Count.Should().BeLessThanOrEqualTo(5);
        AttackCatalog.Search("T1", limit: 0).Should().BeEmpty();
    }
}
