using System.Security.Claims;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Security;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-574: the role claims granted at sign-in are decided from claims alone. A WindowsPrincipal's IsInRole translates
/// the role's name in AD (unbounded, per mapped role, per request), and said yes for an AD group named like the role, so
/// that role's claim was never added.
/// </summary>
public sealed class RoleClaimsTransformerTests
{
    private sealed class Directory : IRoleDirectory
    {
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) =>
            roleNames.Any(r => r == "Manager") ? new HashSet<Permission> { Permission.ViewCases } : new HashSet<Permission>();
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) =>
            adGroups.Contains("SOC-Managers", StringComparer.OrdinalIgnoreCase)
                ? new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Manager" }
                : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public void Invalidate() { }
    }

    /// <summary>Stands in for a WindowsPrincipal whose user is in an AD group called "Manager".</summary>
    private sealed class DirectoryBackedPrincipal(ClaimsIdentity identity) : ClaimsPrincipal(identity)
    {
        public int RoleLookups;
        public override bool IsInRole(string role)
        {
            Interlocked.Increment(ref RoleLookups);
            return true;
        }
    }

    private static DirectoryBackedPrincipal SignIn() => new(new ClaimsIdentity(
        [new Claim(ClaimTypes.Name, @"CORP\jdoe"), new Claim(ClaimTypes.GroupSid, "SOC-Managers")], "Negotiate"));

    [Fact]
    public async Task A_mapped_role_is_granted_without_asking_the_directory()
    {
        var principal = SignIn();

        var result = await new RoleClaimsTransformer(new Directory()).TransformAsync(principal);

        result.FindAll(ClaimTypes.Role).Select(c => c.Value).Should().Equal(["Manager"],
            "an AD group named like the role doesn't stop the role being granted");
        result.HasClaim(AppClaimTypes.Permission, nameof(Permission.ViewCases)).Should().BeTrue();
        principal.RoleLookups.Should().Be(0, "no role check goes to the directory");
    }

    [WindowsFact]
    public void A_bare_name_withheld_because_the_servers_domain_isnt_known_yet_leaves_the_answer_incomplete(/* BUG-575, BUG-615 */)
    {
        const string sid = "S-1-5-21-1-2-3-1001";
        var answer = new SidNames.Answer(new Dictionary<string, string> { [sid] = @"CORP\SOC-Managers" }, new HashSet<string>());

        var unknown = RoleClaimsTransformer.Candidates([sid], answer, serverDomainSid: "");
        unknown.Names.Should().Contain(@"CORP\SOC-Managers").And.NotContain("SOC-Managers", "BUG-188: fail closed");
        unknown.Complete.Should().BeFalse("the bare name may yet map once the domain is found");

        var own = RoleClaimsTransformer.Candidates([sid], answer, serverDomainSid: "S-1-5-21-1-2-3");
        own.Names.Should().Contain("SOC-Managers");
        own.Complete.Should().BeTrue();

        var trusted = RoleClaimsTransformer.Candidates([sid], answer, serverDomainSid: "S-1-5-21-9-9-9");
        trusted.Names.Should().NotContain("SOC-Managers", "another domain's group matches only a mapping that names it");
        trusted.Complete.Should().BeTrue("withheld for a known reason, so nothing is missing");
    }

    [Fact]
    public async Task Transforming_again_adds_nothing()
    {
        var transformer = new RoleClaimsTransformer(new Directory());
        var principal = SignIn();

        await transformer.TransformAsync(principal);
        var identities = principal.Identities.Count();
        var claims = principal.Claims.Count();
        await transformer.TransformAsync(principal);   // a second AuthenticateAsync in the same request

        principal.Identities.Should().HaveCount(identities);
        principal.Claims.Should().HaveCount(claims);
        principal.Identities.Where(i => i.IsAuthenticated).Should().ContainSingle("the grants stay off the signed-in identity (WF-42)");
    }
}
