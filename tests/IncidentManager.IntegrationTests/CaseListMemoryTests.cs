using FluentAssertions;
using IncidentManager.Web.Services;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-474: the workspace's back link returns to the list as it was left, never a bare "cases".</summary>
public sealed class CaseListMemoryTests
{
    [Fact]
    public void A_workspace_reached_without_the_list_keeps_the_fresh_landing_link() =>
        new CaseListMemory().BackHref.Should().Be("cases");

    [Theory]
    [InlineData("https://host/cases", "cases?scope=all")]
    [InlineData("https://host/cases/", "cases?scope=all")]
    [InlineData("https://host/cases?scope=all", "cases?scope=all")]
    [InlineData("https://host/cases?phase=Triage&page=2", "cases?phase=Triage&page=2")]
    [InlineData("https://host/cases?scope=mine", "cases?scope=mine")]
    [InlineData("https://host/cases/mine", "cases?scope=mine")]
    [InlineData("https://host/cases/mine?phase=Triage", "cases?scope=mine&phase=Triage")]
    [InlineData("https://host/cases/mine?scope=all&page=2", "cases?scope=mine&page=2")]
    [InlineData("https://host/app/Cases/Mine/", "cases?scope=mine")]
    public void The_back_link_keeps_the_scope_and_filters(string uri, string expected)
    {
        var memory = new CaseListMemory();
        memory.Remember(uri);
        memory.BackHref.Should().Be(expected);
    }
}
