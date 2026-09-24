using FluentAssertions;
using IncidentManager.Application.Content;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>Markdown → report blocks: the formatting the Word/PDF reports keep (headings, emphasis, lists…).</summary>
public class RichTextTests
{
    [Fact]
    public void Headings_and_emphasis_keep_their_style()
    {
        var blocks = RichText.Parse("## Sequence\nThe **tenant** was *exported* via `rclone`.");

        blocks.Should().HaveCount(2);
        blocks[0].Kind.Should().Be(RichBlockKind.Heading);
        blocks[0].Level.Should().Be(2);
        blocks[0].PlainText.Should().Be("Sequence");

        var runs = blocks[1].Runs;
        runs.Should().ContainSingle(r => r.Text == "tenant" && r.Bold && !r.Italic);
        runs.Should().ContainSingle(r => r.Text == "exported" && r.Italic && !r.Bold);
        runs.Should().ContainSingle(r => r.Text == "rclone" && r.Code);
        blocks[1].PlainText.Should().Be("The tenant was exported via rclone.");
    }

    [Fact]
    public void Nested_bullets_and_numbered_lists_carry_markers_and_depth()
    {
        var blocks = RichText.Parse("- First\n  - Nested\n- Second\n\n3. Three\n4. Four");

        blocks.Select(b => (b.Kind, b.Level, b.Marker, b.PlainText)).Should().Equal(
            (RichBlockKind.Bullet, 0, "•", "First"),
            (RichBlockKind.Bullet, 1, "◦", "Nested"),
            (RichBlockKind.Bullet, 0, "•", "Second"),
            (RichBlockKind.Numbered, 0, "3.", "Three"),
            (RichBlockKind.Numbered, 0, "4.", "Four"));
    }

    [Fact]
    public void Links_print_their_url_but_entity_tags_print_only_the_label()
    {
        var entity = Guid.NewGuid();
        var text = RichText.Parse($"See [the runbook](https://wiki.example/ir) and [FIN-WKS-07](entity:{entity}).")[0].PlainText;

        text.Should().Be("See the runbook (https://wiki.example/ir) and FIN-WKS-07.");
    }

    [Fact]
    public void Quotes_and_code_blocks_are_recognised()
    {
        var blocks = RichText.Parse("> Vendor statement\n\n```\nline one\nline two\n```");

        blocks[0].Kind.Should().Be(RichBlockKind.Quote);
        blocks[0].PlainText.Should().Be("Vendor statement");
        blocks[1].Kind.Should().Be(RichBlockKind.Code);
        blocks[1].PlainText.Should().Be("line one\nline two");
    }

    [Fact]
    public void Raw_html_stays_inert_text()
    {
        RichText.Parse("<b>not bold</b>")[0].Runs.Should().OnlyContain(r => !r.Bold);
    }

    [Fact]
    public void ToText_keeps_list_markers_and_line_breaks_for_table_cells()
    {
        RichText.ToText("Done:\n\n- **Rotated** keys\n  - vaulted\n- Confirmed").Should()
            .Be("Done:\n• Rotated keys\n  ◦ vaulted\n• Confirmed");
        RichText.ToText(null).Should().BeEmpty();
    }
}
