using FluentAssertions;
using IncidentManager.Application.Cases;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// RelatedIndicators.None once held a null Excluded: it was built before the empty dictionary it reads (static fields
/// initialise in declaration order), and the New case page failed to render on every first visit.
/// </summary>
public sealed class RelatedIndicatorsTests
{
    [Fact]
    public void None_is_empty_with_nothing_excluded()
    {
        RelatedIndicators.None.Should().BeEmpty();
        RelatedIndicators.None.Excluded.Should().NotBeNull().And.BeEmpty();
        RelatedIndicators.None.ScanLimitHit.Should().BeFalse();
        RelatedIndicators.None.ExcludedBecause("contoso.com").Should().BeNull();
    }
}
