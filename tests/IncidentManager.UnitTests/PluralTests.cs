using FluentAssertions;
using IncidentManager.Application.Common;
using Xunit;

namespace IncidentManager.UnitTests;

public sealed class PluralTests
{
    [Theory]
    [InlineData(0, "0 cases")]
    [InlineData(1, "1 case")]
    [InlineData(3, "3 cases")]
    public void Regular_nouns_take_an_s_unless_the_count_is_one(int n, string expected) =>
        Plural.Of(n, "case").Should().Be(expected);

    [Fact]
    public void Irregular_plurals_use_the_given_form() =>
        Plural.Of(2, "entry", "entries").Should().Be("2 entries");
}
