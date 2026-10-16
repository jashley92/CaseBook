using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Components.Shared;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// C16 (C4's minor): the pick-list options of an enum taxonomy hide and reorder members only for a kind the catalog lets
/// an admin hide and reorder. A hidden or order setting for the classification ladder or the phases (appsettings, a
/// hand-edited row: the admin page and the import refuse to write one) dropped a rung from every pick-list.
/// </summary>
public class TaxonomyOptionsTests
{
    private sealed class Display(Dictionary<string, string[]> order, HashSet<string> hidden) : ITaxonomyDisplay
    {
        public string Label(string kind, string member, string fallback) => fallback;
        public bool IsHidden(string kind, string member) => hidden.Contains($"{kind}:{member}");
        public IReadOnlyList<string> Order(string kind) => order.TryGetValue(kind, out var o) ? o : [];
    }

    [Fact]
    public void A_kind_without_hide_and_order_lists_every_member_in_its_own_order()
    {
        var display = new Display(
            new() { ["Classification"] = ["Breach", "Incident"], ["CasePhase"] = ["Closed"] },
            ["Classification:Breach", "CasePhase:Triage"]);

        Ui.OptionsFrom<Classification>("Classification", display).Should().Equal(Enum.GetValues<Classification>());
        Ui.OptionsFrom<CasePhase>("CasePhase", display).Should().Equal(Enum.GetValues<CasePhase>());
    }

    [Fact]
    public void A_kind_with_hide_and_order_drops_the_hidden_and_puts_the_listed_first()
    {
        var display = new Display(
            new() { ["EntityDisposition"] = ["Malicious", "Unknown"] },
            ["EntityDisposition:Suspicious"]);

        var options = Ui.OptionsFrom<EntityDisposition>("EntityDisposition", display);

        options.Should().NotContain(EntityDisposition.Suspicious);
        options.Take(2).Should().Equal(EntityDisposition.Malicious, EntityDisposition.Unknown);
        options.Skip(2).Should().Equal(Enum.GetValues<EntityDisposition>()
            .Where(d => d is not (EntityDisposition.Suspicious or EntityDisposition.Malicious or EntityDisposition.Unknown)),
            "unlisted members keep their natural order, after the listed ones");
    }

    [Fact]
    public void Before_the_provider_is_wired_every_member_is_offered()
    {
        Ui.OptionsFrom<EntityType>("EntityType", null).Should().Equal(Enum.GetValues<EntityType>());
    }
}
