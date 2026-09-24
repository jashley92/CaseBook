using FluentAssertions;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>PROD-45: TLP 2.0 markings parse from the ways people write them and print in the standard form.</summary>
public class TlpTests
{
    [Theory]
    [InlineData("AMBER", TlpLevel.Amber)]
    [InlineData("tlp:amber+strict", TlpLevel.AmberStrict)]
    [InlineData("AmberStrict", TlpLevel.AmberStrict)]
    [InlineData(" TLP:RED ", TlpLevel.Red)]
    [InlineData("WHITE", TlpLevel.Clear)]      // TLP 1.0 name
    [InlineData("clear", TlpLevel.Clear)]
    [InlineData("green", TlpLevel.Green)]
    public void Parses(string raw, TlpLevel expected) => Tlp.Parse(raw).Should().Be(expected);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("PURPLE")]
    public void Unknown_is_null(string? raw) => Tlp.Parse(raw).Should().BeNull();

    [Fact]
    public void Labels_are_the_standard_markings() =>
        Enum.GetValues<TlpLevel>().Select(Tlp.Label).Should()
            .Equal("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED");
}
