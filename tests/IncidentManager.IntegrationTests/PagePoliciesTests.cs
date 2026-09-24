using FluentAssertions;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Security;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>S-22: the access-denied page names the permission a refused page needs, read from the pages themselves.</summary>
public class PagePoliciesTests
{
    [Theory]
    [InlineData("/admin/roles", Permission.Administer)]
    [InlineData("admin", Permission.Administer)]
    [InlineData("/team", Permission.ViewAllCases)]
    [InlineData("/cases/new", Permission.EditCases)]
    [InlineData("/cases/6a339aaf-3c92-4130-a26c-46681ec9ccfd?tab=Audit", Permission.ViewCases)]
    public void Knows_what_a_page_requires(string path, Permission expected) =>
        PagePolicies.RequiredFor(path).Should().Be(expected);

    [Theory]
    [InlineData(null)]
    [InlineData("/no/such/page")]
    [InlineData("/export/access-log.csv")]   // an endpoint, not a page
    [InlineData("/account/api-tokens")]      // signed-in only, no permission policy
    public void Unknown_or_policy_free_paths_yield_nothing(string? path) =>
        PagePolicies.RequiredFor(path).Should().BeNull();
}
