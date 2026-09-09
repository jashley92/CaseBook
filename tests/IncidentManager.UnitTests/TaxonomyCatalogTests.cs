using FluentAssertions;
using IncidentManager.Application.Admin;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// X-02: the taxonomy catalog's member values are the override keys. They MUST match the canonical member
/// strings that <c>Ui.Label</c> passes (the enum names, plus "ComplexEvent" for a null classification), or a
/// rename would silently fail to apply. These tests pin that contract.
/// </summary>
public class TaxonomyCatalogTests
{
    [Fact]
    public void Classification_members_are_the_enum_names_plus_complex_event()
    {
        var kind = TaxonomyCatalog.Kinds.Single(k => k.Id == "Classification");
        var expected = new[] { "ComplexEvent" }.Concat(Enum.GetNames<Classification>());
        kind.Members.Select(m => m.Value).Should().BeEquivalentTo(expected);
    }

    [Fact]
    public void CasePhase_members_are_exactly_the_enum_names()
    {
        var kind = TaxonomyCatalog.Kinds.Single(k => k.Id == "CasePhase");
        kind.Members.Select(m => m.Value).Should().BeEquivalentTo(Enum.GetNames<CasePhase>());
    }

    [Theory]
    [InlineData("EntityType", typeof(EntityType))]
    [InlineData("EntityDisposition", typeof(EntityDisposition))]
    [InlineData("TimelineEntryType", typeof(TimelineEntryType))]
    [InlineData("EntityRelationshipType", typeof(EntityRelationshipType))]
    public void Pick_list_kinds_members_are_exactly_their_enum_names(string kindId, Type enumType)
    {
        var kind = TaxonomyCatalog.Kinds.Single(k => k.Id == kindId);
        kind.Members.Select(m => m.Value).Should().BeEquivalentTo(Enum.GetNames(enumType));
    }

    [Fact]
    public void Default_label_helper_returns_the_catalog_default_and_falls_back_to_the_member()
    {
        TaxonomyCatalog.DefaultLabel("EntityType", "IpAddress").Should().Be("IP Address");
        TaxonomyCatalog.DefaultLabel("EntityType", "Nonexistent").Should().Be("Nonexistent");
        TaxonomyCatalog.DefaultLabel("Nonexistent", "Whatever").Should().Be("Whatever");
    }

    [Fact]
    public void Every_member_has_a_non_empty_default_label()
    {
        foreach (var kind in TaxonomyCatalog.Kinds)
            foreach (var m in kind.Members)
                m.DefaultLabel.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Label_key_is_the_stable_taxonomy_prefixed_form()
    {
        TaxonomyCatalog.LabelKey("Classification", "Breach").Should().Be("Taxonomy:Classification:Label:Breach");
        TaxonomyCatalog.LabelKey("Classification", "Breach").Should().StartWith(TaxonomyCatalog.KeyPrefix);
    }

    [Fact]
    public void Hidden_and_order_keys_are_the_stable_taxonomy_prefixed_forms()
    {
        TaxonomyCatalog.HiddenKey("EntityType", "Other").Should().Be("Taxonomy:EntityType:Hidden:Other");
        TaxonomyCatalog.OrderKey("EntityType").Should().Be("Taxonomy:EntityType:Order");
        TaxonomyCatalog.HiddenKey("EntityType", "Other").Should().StartWith(TaxonomyCatalog.KeyPrefix);
        TaxonomyCatalog.OrderKey("EntityType").Should().StartWith(TaxonomyCatalog.KeyPrefix);
    }

    [Fact]
    public void Only_the_non_load_bearing_pick_lists_allow_hide_and_reorder()
    {
        // The ladder and phases stay fixed (X-05); the entity/timeline pick-lists may be hidden/reordered.
        string[] expectedAllowed = ["EntityType", "EntityDisposition", "TimelineEntryType", "EntityRelationshipType"];
        TaxonomyCatalog.Kinds.Where(k => k.AllowVisibilityOrder).Select(k => k.Id)
            .Should().BeEquivalentTo(expectedAllowed);
        TaxonomyCatalog.Kinds.Single(k => k.Id == "Classification").AllowVisibilityOrder.Should().BeFalse();
        TaxonomyCatalog.Kinds.Single(k => k.Id == "CasePhase").AllowVisibilityOrder.Should().BeFalse();
    }
}
