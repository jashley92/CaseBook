using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Application.Branding;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>X-08: the white-label brand palette deriver. The AA-contrast guarantee is verified against an
/// independent WCAG computation in the test, so production's own colour math is never trusted to grade itself.</summary>
public class BrandPaletteTests
{
    [Theory]
    [InlineData(null, null)]
    [InlineData("", "   ")]
    [InlineData("not-a-colour", null)]
    [InlineData("#12", null)]
    public void No_valid_colour_emits_nothing(string? accent, string? ink) =>
        BrandPalette.BuildCss(accent, ink).Should().BeNull();

    [Fact]
    public void An_accent_overrides_the_brand_tokens_for_both_themes()
    {
        var css = BrandPalette.BuildCss("#ffcf31", null)!;
        css.Should().Contain(":root{");
        css.Should().Contain("[data-bs-theme=\"dark\"]{");
        css.Should().Contain("--im-accent:#ffcf31");
        css.Should().Contain("--im-gold:#ffcf31");
    }

    [Fact]
    public void Ink_drives_the_primary_action_roles_including_the_bootstrap_rgb_bridge()
    {
        var css = BrandPalette.BuildCss(null, "#334155")!;
        css.Should().Contain("--im-ink:#334155");
        css.Should().Contain("--bs-primary:#334155");
        css.Should().Contain("--bs-primary-rgb:51, 65, 85");
    }

    // A hard spread: a bright yellow, cyan, near-white, a mid blue, and pure white all start with poor
    // contrast on a light surface and must be pushed to an AA-legible emphasis shade.
    [Theory]
    [InlineData("#ffcf31")]
    [InlineData("#00e5ff")]
    [InlineData("#e6e6e6")]
    [InlineData("#4f8cff")]
    [InlineData("#ffffff")]
    public void The_link_emphasis_shade_meets_AA_on_both_surfaces(string accent)
    {
        var css = BrandPalette.BuildCss(accent, null)!;

        var lightText = Var(Block(css, ":root"), "--im-accent-text");
        var darkText = Var(Block(css, "[data-bs-theme=\"dark\"]"), "--im-accent-text");

        Contrast(lightText, "#ffffff").Should().BeGreaterThanOrEqualTo(4.5, "brand links must be AA on light surfaces");
        Contrast(darkText, "#1a212a").Should().BeGreaterThanOrEqualTo(4.5, "brand links must be AA on dark surfaces");
    }

    [Fact]
    public void The_semantic_status_palette_is_never_rebranded()
    {
        var css = BrandPalette.BuildCss("#4f8cff", "#334155")!;
        // Guardrail (b): red keeps reading as danger regardless of brand.
        css.Should().NotContain("--im-danger");
        css.Should().NotContain("--im-sev-");
        css.Should().NotContain("--im-phase-");
        css.Should().NotContain("--im-ok");
        css.Should().NotContain("--im-warn");
    }

    // --- independent WCAG 2.1 reference computation (kept separate from production code) ---

    private static string Block(string css, string selector)
    {
        var open = css.IndexOf(selector + "{", StringComparison.Ordinal);
        open.Should().BeGreaterThanOrEqualTo(0);
        var start = open + selector.Length + 1;
        var end = css.IndexOf('}', start);
        return css[start..end];
    }

    private static string Var(string block, string name)
    {
        var m = Regex.Match(block, Regex.Escape(name) + @":\s*(#[0-9a-fA-F]{6})");
        m.Success.Should().BeTrue($"{name} should be present");
        return m.Groups[1].Value;
    }

    private static (int R, int G, int B) Parse(string hex)
    {
        var h = hex.TrimStart('#');
        return (Convert.ToInt32(h[..2], 16), Convert.ToInt32(h.Substring(2, 2), 16), Convert.ToInt32(h.Substring(4, 2), 16));
    }

    private static double Lin(int v)
    {
        var s = v / 255.0;
        return s <= 0.03928 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
    }

    private static double Luminance(string hex)
    {
        var (r, g, b) = Parse(hex);
        return 0.2126 * Lin(r) + 0.7152 * Lin(g) + 0.0722 * Lin(b);
    }

    private static double Contrast(string a, string b)
    {
        double la = Luminance(a), lb = Luminance(b);
        var (hi, lo) = la > lb ? (la, lb) : (lb, la);
        return (hi + 0.05) / (lo + 0.05);
    }
}
