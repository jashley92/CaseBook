using FluentAssertions;
using IncidentManager.Application.Content;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// The Markdown rendering used by the Investigation timeline (U-08b): formatting renders, but raw HTML
/// and dangerous link schemes are neutralised so stored notes cannot carry an executable payload.
/// </summary>
public class MarkdownServiceTests
{
    private readonly MarkdownService _md = new();

    [Fact]
    public void Renders_common_formatting_to_html()
    {
        var html = _md.ToHtml("# Heading\n\n- one\n- two\n\n**bold** and *italic*");

        html.Should().Contain("<h1").And.Contain("Heading");
        html.Should().Contain("<ul>").And.Contain("<li>one</li>");
        html.Should().Contain("<strong>bold</strong>");
        html.Should().Contain("<em>italic</em>");
    }

    [Fact]
    public void Escapes_raw_html_so_scripts_do_not_execute()
    {
        var html = _md.ToHtml("Hello <script>alert('xss')</script> world");

        html.Should().NotContain("<script>");
        html.Should().Contain("&lt;script&gt;");   // rendered as visible text, not live markup
    }

    [Theory]
    [InlineData("[click](javascript:alert(1))")]
    [InlineData("[click](data:text/html,<script>alert(1)</script>)")]
    [InlineData("[click](vbscript:msgbox)")]
    public void Neutralises_dangerous_link_schemes(string markdown)
    {
        var html = _md.ToHtml(markdown);

        html.Should().NotContain("javascript:");
        html.Should().NotContain("vbscript:");
        html.Should().NotContain("data:text/html");
        html.Should().Contain("href=\"#\"");   // rewritten to an inert anchor
    }

    [Theory]
    [InlineData("[docs](https://example.com/page)", "https://example.com/page")]
    [InlineData("[mail](mailto:soc@example.com)", "mailto:soc@example.com")]
    public void Keeps_safe_link_schemes(string markdown, string expectedHref)
    {
        _md.ToHtml(markdown).Should().Contain(expectedHref);
    }

    [Fact]
    public void PlainText_strips_formatting_for_reports()
    {
        var text = _md.ToPlainText("# Title\n\n- alpha\n- beta\n\n**strong**");

        text.Should().Contain("Title");
        text.Should().Contain("alpha").And.Contain("beta");
        text.Should().NotContain("#").And.NotContain("**");
    }

    [Fact]
    public void Empty_input_is_empty_output()
    {
        _md.ToHtml(null).Should().BeEmpty();
        _md.ToHtml("   ").Should().BeEmpty();
        _md.ToPlainText(null).Should().BeEmpty();
    }
}
