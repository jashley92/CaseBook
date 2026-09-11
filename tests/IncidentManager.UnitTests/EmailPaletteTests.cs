using FluentAssertions;
using IncidentManager.Application.Branding;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>E-03b: the email palette resolves the console theme to literal hex, with the built-in defaults.</summary>
public class EmailPaletteTests
{
    [Fact]
    public void Defaults_to_the_built_in_gold_and_charcoal()
    {
        var p = BrandPalette.EmailColors(null, null);
        p.Accent.Should().Be("#ffcf31");     // gold
        p.ButtonBg.Should().Be("#232a33");   // charcoal ink
        p.ButtonText.Should().Be("#ffffff"); // white is legible on charcoal
    }

    [Fact]
    public void Honours_a_custom_accent_and_ink()
    {
        var p = BrandPalette.EmailColors("#3366cc", "#101820");
        p.Accent.Should().Be("#3366cc");
        p.HeaderBg.Should().Be("#101820");
        p.ButtonBg.Should().Be("#101820");
    }

    [Fact]
    public void Falls_back_to_defaults_for_an_invalid_hex()
    {
        var p = BrandPalette.EmailColors("not-a-colour", "");
        p.Accent.Should().Be("#ffcf31");
        p.ButtonBg.Should().Be("#232a33");
    }
}
