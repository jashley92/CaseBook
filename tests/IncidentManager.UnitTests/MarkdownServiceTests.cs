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
    public void Entity_tag_links_deep_link_to_the_entities_tab_when_the_case_is_known()
    {
        var caseId = Guid.Parse("11111111-2222-3333-4444-555555555555");
        var html = _md.ToHtml("Traced it to [FIN-WKS-07](entity:3f2504e0-4f89-41d3-9a0c-0305e82c3301).", caseId);

        html.Should().Contain("class=\"im-entity-tag\"");
        html.Should().Contain("FIN-WKS-07");
        html.Should().Contain("href=\"/cases/11111111-2222-3333-4444-555555555555?tab=Entities&amp;entity=3f2504e0-4f89-41d3-9a0c-0305e82c3301\"");
        html.Should().NotContain("entity:");   // the raw scheme never reaches an href
    }

    [Fact]
    public void Entity_tag_without_a_case_context_renders_a_non_navigating_chip()
    {
        var html = _md.ToHtml("[FIN-WKS-07](entity:3f2504e0-4f89-41d3-9a0c-0305e82c3301)");

        html.Should().Contain("class=\"im-entity-tag\"").And.Contain("FIN-WKS-07");
        html.Should().NotContain("<a ");        // no case → not a link
    }

    [Fact]
    public void A_malformed_entity_reference_degrades_to_a_non_navigating_chip()
    {
        var html = _md.ToHtml("[x](entity:not-a-guid)", Guid.NewGuid());

        html.Should().Contain("class=\"im-entity-tag\"");
        html.Should().NotContain("<a ");        // no anchor for an unvalidated id
        html.Should().NotContain("entity:");
    }

    [Fact]
    public void Entity_tag_reduces_to_its_label_in_report_plain_text()
    {
        _md.ToPlainText("See [CONTOSO\\jdoe](entity:abc).").Should().Contain("CONTOSO\\jdoe").And.NotContain("entity:");
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
