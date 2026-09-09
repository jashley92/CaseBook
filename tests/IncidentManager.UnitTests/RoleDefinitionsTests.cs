using FluentAssertions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

public class RoleDefinitionsTests
{
    [Fact]
    public void SysAdmin_holds_every_permission()
    {
        var perms = RoleDefinitions.PermissionsFor([AppRole.SysAdmin]);
        perms.Should().BeEquivalentTo(Enum.GetValues<Permission>());
    }

    [Fact]
    public void Analyst_is_limited_to_view_and_edit()
    {
        var perms = RoleDefinitions.PermissionsFor([AppRole.Analyst]);

        perms.Should().BeEquivalentTo([Permission.ViewCases, Permission.EditCases]);
        perms.Should().NotContain(Permission.ViewAllCases);   // scoped by need-to-know
        perms.Should().NotContain(Permission.Administer);
    }

    [Theory]
    [InlineData(AppRole.Manager)]
    [InlineData(AppRole.LegalPrivacy)]
    [InlineData(AppRole.SysAdmin)]
    public void Oversight_roles_can_see_all_cases(AppRole role) =>
        RoleDefinitions.PermissionsFor([role]).Should().Contain(Permission.ViewAllCases);

    [Theory]
    [InlineData(AppRole.Analyst)]
    [InlineData(AppRole.IncidentCommander)]
    public void Working_roles_are_scoped_by_need_to_know(AppRole role) =>
        RoleDefinitions.PermissionsFor([role]).Should().NotContain(Permission.ViewAllCases);

    [Fact]
    public void Permissions_are_the_union_across_roles()
    {
        var perms = RoleDefinitions.PermissionsFor([AppRole.Analyst, AppRole.LegalPrivacy]);

        perms.Should().Contain(Permission.EditCases)     // from Analyst
             .And.Contain(Permission.ManageLegal)        // from LegalPrivacy
             .And.Contain(Permission.ViewAllCases);
    }

    [Fact]
    public void Role_names_parse_and_unknown_names_are_ignored()
    {
        var perms = RoleDefinitions.PermissionsForRoleNames(["sysadmin", "not-a-role"]);
        perms.Should().BeEquivalentTo(Enum.GetValues<Permission>());
    }
}
