using FluentAssertions;
using IncidentManager.Web.Components.Pages.Workspace;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-489: the workspace's synced address says where the viewer is now, not what the page was opened with.</summary>
public sealed class CaseViewsUrlTests
{
    private static readonly Guid CaseId = Guid.Parse("6f1d2c3b-0000-4000-8000-000000000001");
    private static readonly Guid FileId = Guid.Parse("6f1d2c3b-0000-4000-8000-000000000002");

    [Fact]
    public void It_carries_the_part_and_nothing_else_when_no_panel_is_open()
    {
        var url = CaseViews.Url(CaseId, "Tasks");

        url.Should().Be($"cases/{CaseId}?tab=Tasks");
        url.Should().NotContain("entry=").And.NotContain("note=").And.NotContain("entity=").And.NotContain("evidence=",
            "a closed panel and a spent deep link don't come back on a refresh or through the tab strip");
    }

    [Fact]
    public void An_open_evidence_panel_is_carried_so_a_refresh_reopens_it()
    {
        CaseViews.Url(CaseId, "Timeline", FileId).Should().Be($"cases/{CaseId}?tab=Timeline&evidence={FileId}");
    }

    [Fact]
    public void The_part_is_escaped_and_reads_back_as_the_same_part()
    {
        var url = CaseViews.Url(CaseId, "Closeout");
        var tab = Uri.UnescapeDataString(url[(url.IndexOf("tab=", StringComparison.Ordinal) + 4)..]);

        tab.Should().Be("Closeout");
        CaseViews.Url(CaseId, "a&b").Should().EndWith("tab=a%26b");
    }
}
