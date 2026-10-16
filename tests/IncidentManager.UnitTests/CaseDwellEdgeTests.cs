using FluentAssertions;
using IncidentManager.Domain.Entities;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>C12: the ten-year dwell check is safe at the start of the calendar.</summary>
public sealed class CaseDwellEdgeTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    public void A_detection_in_the_first_ten_years_does_not_throw_on_the_date_arithmetic(int year)
    {
        var detected = new DateTimeOffset(year, 6, 1, 0, 0, 0, TimeSpan.Zero);
        var act = () => Case.EnsurePlausibleDwell(DateTimeOffset.MinValue, detected);
        act.Should().NotThrow();
    }

    [Fact]
    public void More_than_ten_years_before_detection_is_still_refused()
    {
        var detected = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
        var act = () => Case.EnsurePlausibleDwell(detected.AddYears(-11), detected);
        act.Should().Throw<ArgumentException>();
    }
}
