using System.Security.Claims;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Security;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// S-14: <see cref="CurrentUser.RoleNames"/> lists every CaseBook role the user holds — built-in and custom — and
/// drops role claims that aren't CaseBook roles (Windows can carry group SIDs as role claims).
/// </summary>
public sealed class CurrentUserRoleNamesTests
{
    [Fact]
    public void Custom_roles_are_listed_and_group_sids_are_dropped()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, "u1"),
            new Claim(ClaimTypes.Role, "Analyst"),
            new Claim(ClaimTypes.Role, "Insider Response"),
            new Claim(ClaimTypes.Role, "S-1-5-21-1111-2222-3333-513"),
            new Claim(ClaimTypes.Role, "insider response"), // duplicate, different case
        ], authenticationType: "Test"));
        var http = new HttpContextAccessor { HttpContext = new DefaultHttpContext { User = principal } };

        var user = new CurrentUser(http, new NoAuthState(),
            new ServiceCollection().AddSingleton<IRoleDirectory>(new Directory("Insider Response")).BuildServiceProvider());

        user.RoleNames.Should().BeEquivalentTo(["Analyst", "Insider Response"]);
        user.Roles.Should().BeEquivalentTo([AppRole.Analyst]); // built-in view unchanged
    }

    private sealed class NoAuthState : AuthenticationStateProvider
    {
        public override Task<AuthenticationState> GetAuthenticationStateAsync() =>
            Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));
    }

    private sealed class Directory(params string[] custom) : IRoleDirectory
    {
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) => new HashSet<Permission>();
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) => new HashSet<string>();
        public bool IsRole(string name) => custom.Contains(name, StringComparer.OrdinalIgnoreCase);
        public void Invalidate() { }
    }
}
