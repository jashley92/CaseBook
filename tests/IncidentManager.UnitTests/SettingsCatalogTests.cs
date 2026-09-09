using FluentAssertions;
using IncidentManager.Application.Admin;
using Xunit;

namespace IncidentManager.UnitTests;

public class SettingsCatalogTests
{
    private static SettingDefinition Def(SettingKind kind) =>
        new("Test:Key", "Test", "Group", kind, "desc");

    [Theory]
    [InlineData("true", "true")]
    [InlineData("  TRUE ", "true")]
    [InlineData("false", "false")]
    public void Normalize_bool_canonicalizes(string input, string expected) =>
        SettingsCatalog.Normalize(Def(SettingKind.Bool), input).Should().Be(expected);

    [Fact]
    public void Normalize_bool_rejects_garbage()
    {
        var act = () => SettingsCatalog.Normalize(Def(SettingKind.Bool), "yes");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Normalize_int_accepts_non_negative_and_rejects_the_rest()
    {
        SettingsCatalog.Normalize(Def(SettingKind.Int), " 7 ").Should().Be("7");
        SettingsCatalog.Normalize(Def(SettingKind.Int), "").Should().BeNull();

        var negative = () => SettingsCatalog.Normalize(Def(SettingKind.Int), "-1");
        negative.Should().Throw<ArgumentException>();
        var words = () => SettingsCatalog.Normalize(Def(SettingKind.Int), "lots");
        words.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Normalize_multitext_trims_lines_and_drops_blanks()
    {
        var input = "  a@x.com \r\n\r\n b@x.com  \n";
        SettingsCatalog.Normalize(Def(SettingKind.MultiText), input)
            .Should().Be("a@x.com\nb@x.com");
    }

    [Fact]
    public void Catalog_excludes_security_and_infrastructure_keys()
    {
        // The editable whitelist must never expose secrets or infra plumbing.
        SettingsCatalog.IsEditable("ConnectionStrings:Default").Should().BeFalse();
        SettingsCatalog.IsEditable("Auth:Mode").Should().BeFalse();
        SettingsCatalog.IsEditable("Integrity:SigningKeyPath").Should().BeFalse();

        SettingsCatalog.IsEditable("Email:From").Should().BeTrue();
    }
}
