using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>INV-49: a relationship's type, description and direction are corrected in place, as one change.</summary>
public class EntityRelationshipEditTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 25, 12, 0, 0, TimeSpan.Zero);

    private static (Case c, CaseEntity ip, CaseEntity acct, EntityRelationship rel) Setup()
    {
        var c = Case.Open(2026, 7, "Phish", "Credential phishing", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "ic1", T0);
        var ip = c.AddEntity(EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Malicious, null, null, "ic1", T0);
        var acct = c.AddEntity(EntityType.Account, "jdoe", "John Doe", EntityDisposition.Compromised, null, null, "ic1", T0);
        var rel = c.LinkEntities(acct.Id, ip.Id, EntityRelationshipType.CommunicatedWith, null, "ic1", T0);
        return (c, ip, acct, rel);
    }

    [Fact]
    public void Swapping_direction_and_changing_type_updates_the_same_relationship()
    {
        var (c, ip, acct, rel) = Setup();

        c.EditRelationship(rel.Id, ip.Id, acct.Id, EntityRelationshipType.Accessed, "  Session into the mailbox ", "analyst1", T0.AddHours(1));

        c.EntityRelationships.Should().ContainSingle();
        rel.SourceEntityId.Should().Be(ip.Id);
        rel.TargetEntityId.Should().Be(acct.Id);
        rel.Type.Should().Be(EntityRelationshipType.Accessed);
        rel.Description.Should().Be("Session into the mailbox");
        rel.ModifiedBy.Should().Be("analyst1");
        rel.CreatedBy.Should().Be("ic1");
    }

    [Fact]
    public void An_edit_that_would_duplicate_another_relationship_or_link_an_entity_to_itself_is_refused()
    {
        var (c, ip, acct, rel) = Setup();
        c.LinkEntities(ip.Id, acct.Id, EntityRelationshipType.Accessed, null, "ic1", T0);

        c.Invoking(x => x.EditRelationship(rel.Id, ip.Id, acct.Id, EntityRelationshipType.Accessed, null, "ic1", T0))
            .Should().Throw<ArgumentException>().WithMessage("*already exists*");
        c.Invoking(x => x.EditRelationship(rel.Id, ip.Id, ip.Id, EntityRelationshipType.Accessed, null, "ic1", T0))
            .Should().Throw<ArgumentException>();
    }

    [Fact]
    public void An_unchanged_edit_records_nothing()
    {
        var (c, _, _, rel) = Setup();

        c.EditRelationship(rel.Id, rel.SourceEntityId, rel.TargetEntityId, rel.Type, "  ", "analyst1", T0.AddHours(1));

        rel.ModifiedBy.Should().BeNull();
    }
}
