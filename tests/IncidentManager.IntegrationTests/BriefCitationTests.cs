using FluentAssertions;
using IncidentManager.Application.Content;
using IncidentManager.Web.Components.Pages.CaseTabs;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// C13: citing an evidence file in the brief's Known. The file's name is the link's label; brackets in it used to become
/// parentheses ("scan[1].csv" cited as "scan(1).csv", a file the case doesn't have).
/// </summary>
public class BriefCitationTests
{
    private static readonly Guid Id = Guid.Parse("0f8e2c4a-1b3d-4e5f-9a6b-7c8d9e0f1a2b");
    private static readonly (Guid, string?, string)[] NoEntities = [];

    [Fact]
    public void A_plain_name_is_cited_as_a_tag_that_saves_as_its_evidence_link()
    {
        var refs = new Dictionary<string, string>(StringComparer.Ordinal);
        var cite = CaseBriefCard.Citation(@"C:\Temp\audit.csv", Id, refs);

        cite.Should().Be(@"[[C:\Temp\audit.csv]]");
        TagText.FromEditable("- " + cite, refs, NoEntities).Should().Be($@"- [C:\\Temp\\audit.csv](evidence:{Id})");
    }

    [Fact]
    public void A_name_with_brackets_is_cited_as_its_link_with_the_label_escaped_and_kept_by_a_save()
    {
        var refs = new Dictionary<string, string>(StringComparer.Ordinal);
        var cite = CaseBriefCard.Citation("scan[1].csv", Id, refs);

        cite.Should().Be($@"[scan\[1\].csv](evidence:{Id})");
        refs.Should().BeEmpty("there's no [[tag]] to resolve");
        TagText.FromEditable("- " + cite, refs, NoEntities).Should().Be("- " + cite, "a save leaves the link as it is");
        new MarkdownService().ToHtml(cite, Guid.NewGuid()).Should().Contain("im-evidence-tag").And.Contain("scan[1].csv</a>",
            "it shows as the file's chip, under the file's own name");
    }

    [Fact]
    public void A_line_break_in_a_name_doesnt_end_the_link()
    {
        CaseBriefCard.Citation("a\r\nb.csv", Id, new Dictionary<string, string>()).Should().Be("[[a b.csv]]");
    }
}
