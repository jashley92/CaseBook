using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

public class CaseImpactAssessmentTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 11, 0, 0, 0, TimeSpan.Zero);

    private static Case New() => Case.Open(
        2026, 1, "Test", "Test case",
        Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "ic1", Now);

    [Fact]
    public void SetImpactAssessment_records_element_keys_and_normalizes_states()
    {
        var c = New();

        c.SetImpactAssessment(1500, new[] { "Name", "SocialSecurityNumber" }, "ny, nj , ny", "analyst1", Now);

        c.AffectedIndividualsCount.Should().Be(1500);
        c.DataElements.Select(d => d.ElementKey).Should().BeEquivalentTo(new[] { "Name", "SocialSecurityNumber" });
        c.AffectedStates.Should().Be("NY, NJ"); // uppercased, trimmed, de-duplicated, comma-space (U-47a)
    }

    [Fact]
    public void SetImpactAssessment_reconciles_the_element_set_minimally()
    {
        var c = New();
        c.SetImpactAssessment(1, new[] { "Name", "PaymentCard" }, null, "a", Now);
        var nameLink = c.DataElements.Single(d => d.ElementKey == "Name");

        // Re-saving with Name kept + DateOfBirth added, PaymentCard dropped: the Name row survives untouched.
        c.SetImpactAssessment(1, new[] { "Name", "DateOfBirth" }, null, "a", Now);

        c.DataElements.Select(d => d.ElementKey).Should().BeEquivalentTo(new[] { "Name", "DateOfBirth" });
        c.DataElements.Single(d => d.ElementKey == "Name").Should().BeSameAs(nameLink, "an unchanged link is not churned");
    }

    [Fact]
    public void SetImpactAssessment_rejects_a_negative_count()
    {
        var c = New();
        var act = () => c.SetImpactAssessment(-1, Array.Empty<string>(), null, "analyst1", Now);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Impact_fields_are_part_of_the_tamper_evident_canonical_content()
    {
        var c = New();
        var before = c.BuildCanonicalContent();

        c.SetImpactAssessment(10, new[] { "PaymentCard" }, "NY", "analyst1", Now);

        c.BuildCanonicalContent().Should().NotBe(before);
    }

    [Fact]
    public void The_canonical_element_projection_is_order_independent()
    {
        var a = New();
        a.SetImpactAssessment(10, new[] { "Name", "PaymentCard" }, "NY", "x", Now);
        var b = New();
        b.SetImpactAssessment(10, new[] { "PaymentCard", "Name" }, "NY", "x", Now);

        // Keys are sorted in the canonical, so selection order can't change the hash-relevant projection.
        a.BuildCanonicalContent().Should().Be(b.BuildCanonicalContent());
    }
}
