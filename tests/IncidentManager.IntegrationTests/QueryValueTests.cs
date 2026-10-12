using FluentAssertions;
using IncidentManager.Web.Components.Shared;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-31: a bad query-string value is ignored rather than breaking the page.</summary>
public sealed class QueryValueTests
{
    [Theory]
    [InlineData("true", true)]
    [InlineData("True", true)]
    [InlineData("1", true)]
    [InlineData("on", true)]
    [InlineData("false", false)]
    [InlineData("0", false)]
    [InlineData("banana", false)]
    [InlineData(null, false)]
    public void Flags_read_common_spellings(string? raw, bool expected) => QueryValue.Flag(raw).Should().Be(expected);

    [Fact]
    public void Numbers_and_ids_that_do_not_parse_are_null()
    {
        QueryValue.Int("3").Should().Be(3);
        QueryValue.Int("x").Should().BeNull();
        QueryValue.Id("6f1c2a7e-0000-4000-8000-000000000001").Should().NotBeNull();
        QueryValue.Id("6f1c2a7e-0000").Should().BeNull();
    }
}
