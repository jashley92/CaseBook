using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Content;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>BUG-533: the copied briefing's "What remains" has the open questions the page shows, prose included.</summary>
public sealed class BriefingRemainsTests
{
    private readonly MarkdownService _md = new();
    private string Plain(string md) => _md.ToPlainText(md).Trim();

    [Fact]
    public void Prose_questions_are_copied_as_written()
    {
        var (prose, items) = BriefingRemains.Parts("Was the **VPN** the way in?");
        prose.Should().Be("Was the **VPN** the way in?");
        items.Should().BeEmpty();
        BriefingRemains.Lines("Was the **VPN** the way in?", Plain).Should().Equal("Was the VPN the way in?");
    }

    [Fact]
    public void Prose_before_a_list_comes_first_then_each_question()
    {
        const string open = "We still need the firewall logs.\n- Who ran **psexec**?\n- Was data staged?";
        var (prose, items) = BriefingRemains.Parts(open);
        prose.Should().Be("We still need the firewall logs.");
        items.Should().Equal("Who ran **psexec**?", "Was data staged?");
        BriefingRemains.Lines(open, Plain).Should().Equal("We still need the firewall logs.", "? Who ran psexec?", "? Was data staged?");
    }

    [Fact]
    public void A_list_and_no_questions_copy_as_before()
    {
        BriefingRemains.Lines("- One?\n- Two?", Plain).Should().Equal("? One?", "? Two?");
        BriefingRemains.Lines(null, Plain).Should().BeEmpty();
        BriefingRemains.Lines("  ", Plain).Should().BeEmpty();
        BriefingRemains.Parts(null).Prose.Should().BeNull();
        BriefingRemains.Parts(null).Items.Should().BeEmpty();
    }

    [Fact]
    public void Prose_after_a_list_keeps_the_whole_part_as_prose()
    {
        const string open = "- One?\nThen some prose.";
        BriefingRemains.Parts(open).Prose.Should().Be(open);
        BriefingRemains.Parts(open).Items.Should().BeEmpty();
    }
}
