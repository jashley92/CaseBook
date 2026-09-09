using FluentAssertions;
using IncidentManager.Application.Admin;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// X-03: the seeded data-element <b>keys</b> are the stable identity a case stores and the canonical hashes,
/// so they must be unique and well-formed. These pin that contract.
/// </summary>
public class DataElementCatalogTests
{
    [Fact]
    public void Seeds_the_thirteen_default_categories()
    {
        DataElementCatalog.Defaults.Should().HaveCount(13);
        DataElementCatalog.Defaults.Select(d => d.Key).Should().Contain(
            new[] { "Name", "SocialSecurityNumber", "PaymentCard", "MedicalOrHealthInfo", "BiometricData" });
    }

    [Fact]
    public void Keys_are_unique_and_labels_non_empty()
    {
        DataElementCatalog.Defaults.Select(d => d.Key).Should().OnlyHaveUniqueItems();
        DataElementCatalog.Defaults.Should().OnlyContain(d => !string.IsNullOrWhiteSpace(d.Key));
        DataElementCatalog.Defaults.Should().OnlyContain(d => !string.IsNullOrWhiteSpace(d.Label));
    }

    [Fact]
    public void Sort_order_is_the_declaration_sequence_one_through_thirteen()
    {
        DataElementCatalog.Defaults.Select(d => d.SortOrder).Should().Equal(Enumerable.Range(1, 13));
    }
}
