using FluentAssertions;
using IncidentManager.Web.Security;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-188: a group mapping by bare name ("SOC-AppAdmins") matches that group in the server's own domain only, so a
/// same-named group someone makes in a trusted domain doesn't get its role.
/// </summary>
public sealed class GroupNameDomainTests
{
    private const string ServerDomain = "S-1-5-21-1111111111-2222222222-3333333333";
    private const string OtherDomain = "S-1-5-21-4444444444-5555555555-6666666666";

    [WindowsFact]
    public void A_group_of_the_servers_domain_matches_by_bare_name() =>
        RoleClaimsTransformer.IsLocalToServer($"{ServerDomain}-1104", "CORP", "WEB01", ServerDomain).Should().BeTrue();

    [WindowsFact]
    public void A_same_named_group_of_another_domain_does_not() =>
        RoleClaimsTransformer.IsLocalToServer($"{OtherDomain}-1104", "CHILD", "WEB01", ServerDomain).Should().BeFalse();

    [WindowsFact]
    public void Local_and_built_in_groups_do()
    {
        RoleClaimsTransformer.IsLocalToServer($"{OtherDomain}-1001", "WEB01", "WEB01", ServerDomain).Should().BeTrue();
        RoleClaimsTransformer.IsLocalToServer("S-1-5-32-544", "BUILTIN", "WEB01", ServerDomain).Should().BeTrue();
    }

    [WindowsFact]
    public void Off_a_domain_there_is_nothing_to_tell_apart() =>
        RoleClaimsTransformer.IsLocalToServer($"{OtherDomain}-1104", "CHILD", "WEB01", null).Should().BeTrue();
}
