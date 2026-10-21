using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// UX-51: one visual language. Sizes, colours and corner radii come from the design tokens in app.css's <c>:root</c>
/// (in app.css, the components' scoped *.razor.css and their style attributes)
/// (<c>--im-text-*</c>, <c>--im-*</c> colours, <c>--im-radius*</c>), not from values written into a rule or a
/// component's <c>style</c>. The 2026-10-21 audit found 31 font sizes in use and 9 label styles because screens wrote
/// their own. This is a ratchet: the counts may only go down. A new raw value fails (use a token, or add one); a screen
/// moved onto the tokens lowers its count, and the baseline here must be lowered with it, so the gain is kept.
/// </summary>
public sealed partial class DesignTokenGuardTests
{
    // The counts as of the design-system branch's start (v1.15.0). Lower them as screens move onto the tokens.
    private const int CssRawFontSizes = 9;
    private const int CssRawColours = 123;
    private const int CssRawRadii = 33;
    private const int InlineRawFontSizes = 3;
    private const int InlineRawColours = 9;

    [Fact]
    public void Stylesheet_sizes_colours_and_radii_come_from_the_tokens()
    {
        // app.css and the components' scoped stylesheets (*.razor.css).
        var css = StripComments(string.Join('\n',
            Directory.EnumerateFiles(Path.Combine(WebRoot(), "Components"), "*.razor.css", SearchOption.AllDirectories)
                .Append(Path.Combine(WebRoot(), "wwwroot", "app.css"))
                .Select(File.ReadAllText)));
        var decls = Declaration().Matches(css).Select(m => (Prop: m.Groups[1].Value, Value: m.Groups[2].Value.Trim())).ToList();

        var sizes = decls.Count(d => d.Prop == "font-size" && Digit().IsMatch(d.Value) && !d.Value.Contains("var(", StringComparison.Ordinal));
        var colours = decls.Count(d => !d.Prop.StartsWith("--", StringComparison.Ordinal) && LiteralColour().IsMatch(d.Value));
        var radii = decls.Count(d => d.Prop.Contains("radius", StringComparison.Ordinal) && !d.Prop.StartsWith("--", StringComparison.Ordinal)
                                     && !d.Value.Contains("var(", StringComparison.Ordinal) && !AllowedRadius.Contains(d.Value));

        Ratchet("raw font sizes in the stylesheets (use --im-text-*)", sizes, CssRawFontSizes);
        Ratchet("raw colours in the stylesheets (use the --im-* colour tokens)", colours, CssRawColours);
        Ratchet("raw corner radii in the stylesheets (use --im-radius*)", radii, CssRawRadii);
    }

    [Fact]
    public void Components_set_no_sizes_or_colours_inline()
    {
        int sizes = 0, colours = 0;
        foreach (var file in Directory.EnumerateFiles(Path.Combine(WebRoot(), "Components"), "*.razor", SearchOption.AllDirectories))
            foreach (Match m in StyleAttribute().Matches(File.ReadAllText(file)))
            {
                var style = m.Groups[1].Value;
                if (InlineFontSize().IsMatch(style) && !style.Contains("var(", StringComparison.Ordinal)) sizes++;
                if (LiteralColour().IsMatch(style)) colours++;
            }

        Ratchet("raw font sizes in a component's style attribute", sizes, InlineRawFontSizes);
        Ratchet("raw colours in a component's style attribute", colours, InlineRawColours);
    }

    private static readonly HashSet<string> AllowedRadius = new(StringComparer.Ordinal) { "0", "50%", "999px", "inherit", "0 !important" };

    private static void Ratchet(string what, int actual, int baseline)
    {
        actual.Should().BeLessThanOrEqualTo(baseline,
            $"there are {actual} {what}, more than the {baseline} allowed: use a token (UX-51)");
        actual.Should().Be(baseline,
            $"there are now {actual} {what}, fewer than the baseline of {baseline}: lower the baseline in DesignTokenGuardTests so it stays down");
    }

    private static string StripComments(string css) => CssComment().Replace(css, "");

    private static string WebRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var web = Path.Combine(dir.FullName, "src", "IncidentManager.Web");
            if (Directory.Exists(web)) return web;
        }
        throw new DirectoryNotFoundException("src/IncidentManager.Web not found above the test output.");
    }

    [GeneratedRegex(@"/\*.*?\*/", RegexOptions.Singleline)]
    private static partial Regex CssComment();

    [GeneratedRegex(@"(?<![-\w])([a-z-]+)\s*:\s*([^;{}]+)")]
    private static partial Regex Declaration();

    [GeneratedRegex(@"\d")]
    private static partial Regex Digit();

    [GeneratedRegex(@"#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(")]
    private static partial Regex LiteralColour();

    [GeneratedRegex("style=\"([^\"]*)\"")]
    private static partial Regex StyleAttribute();

    [GeneratedRegex(@"font-size\s*:\s*[^;]*\d")]
    private static partial Regex InlineFontSize();
}
