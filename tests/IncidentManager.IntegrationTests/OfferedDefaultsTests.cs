using FluentAssertions;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Components.Pages.CaseTabs;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-506: the Things tab's defaults and detected types are ones its selects offer.</summary>
public class OfferedDefaultsTests
{
    [Fact]
    public void A_default_the_select_offers_is_kept()
    {
        CaseEntitiesTab.OfferedOr(EntityDisposition.Suspicious,
                [EntityDisposition.Unknown, EntityDisposition.Suspicious, EntityDisposition.Malicious])
            .Should().Be(EntityDisposition.Suspicious);
    }

    [Fact]
    public void A_hidden_default_becomes_the_first_offered()
    {
        CaseEntitiesTab.OfferedOr(EntityDisposition.Suspicious, [EntityDisposition.Unknown, EntityDisposition.Malicious])
            .Should().Be(EntityDisposition.Unknown);
        CaseEntitiesTab.OfferedOr(EntityRelationshipType.CommunicatedWith, [EntityRelationshipType.RelatedTo])
            .Should().Be(EntityRelationshipType.RelatedTo);
    }

    [Fact]
    public void With_nothing_offered_the_default_stands()
    {
        CaseEntitiesTab.OfferedOr(EntityType.IpAddress, []).Should().Be(EntityType.IpAddress);
    }

    [Fact]
    public void A_detected_type_is_used_only_when_offered()
    {
        IReadOnlyList<EntityType> all = Enum.GetValues<EntityType>();
        CaseEntitiesTab.DetectedOr(EntityType.IpAddress, EntityType.Domain, all).Should().Be(EntityType.IpAddress);

        IReadOnlyList<EntityType> noIp = all.Where(t => t != EntityType.IpAddress).ToList();
        CaseEntitiesTab.DetectedOr(EntityType.IpAddress, EntityType.Domain, noIp)
            .Should().Be(EntityType.Other, "an IP isn't a domain; Other is the type for what wasn't detected");

        IReadOnlyList<EntityType> noIpNoOther = noIp.Where(t => t != EntityType.Other).ToList();
        CaseEntitiesTab.DetectedOr(EntityType.IpAddress, EntityType.Domain, noIpNoOther).Should().Be(EntityType.Domain);
        CaseEntitiesTab.DetectedOr(EntityType.IpAddress, EntityType.Other, noIpNoOther).Should().Be(noIpNoOther[0]);
    }
}
