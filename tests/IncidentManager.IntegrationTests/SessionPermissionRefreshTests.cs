using System.Security.Claims;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Security;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// S-10: an open session's roles and permissions follow the current role directory, so removing an AD mapping or
/// editing a role reaches signed-in users without them reconnecting.
/// </summary>
public sealed class SessionPermissionRefreshTests
{
    /// <summary>A mutable directory: AD group → roles, role → permissions.</summary>
    private sealed class Directory : IRoleDirectory
    {
        public Dictionary<string, HashSet<string>> Groups { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, HashSet<Permission>> Roles { get; } = new(StringComparer.OrdinalIgnoreCase);

        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) =>
            roleNames.SelectMany(r => Roles.TryGetValue(r, out var p) ? p : []).ToHashSet();
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) =>
            adGroups.SelectMany(g => Groups.TryGetValue(g, out var r) ? r : []).ToHashSet(StringComparer.OrdinalIgnoreCase);
        public bool IsRole(string name) => Roles.ContainsKey(name);
        public void Invalidate() { }
    }

    private static Directory Standard()
    {
        var d = new Directory();
        d.Roles["Analyst"] = [Permission.ViewCases, Permission.EditCases];
        d.Roles["IncidentCommander"] = [Permission.ViewCases, Permission.EditCases, Permission.ApproveReports];
        d.Groups["SOC-Analysts"] = ["Analyst"];
        d.Groups["SOC-ICs"] = ["IncidentCommander"];
        return d;
    }

    /// <summary>A Windows-style principal: the Negotiate identity with its groups, plus the transformer's grants.</summary>
    private static ClaimsPrincipal WindowsUser(Directory d, params string[] groups)
    {
        var windows = new ClaimsIdentity(
            new[] { new Claim(ClaimTypes.Name, @"CORP\jdoe") }.Concat(groups.Select(g => new Claim(ClaimTypes.GroupSid, g))),
            "Negotiate");
        var roles = d.RolesForGroups(groups);
        var granted = new ClaimsIdentity(
            roles.Select(r => new Claim(ClaimTypes.Role, r))
                .Concat(d.PermissionsForRoles(roles).Select(p => new Claim(AppClaimTypes.Permission, p.ToString()))));
        return new ClaimsPrincipal([windows, granted]);
    }

    private static IEnumerable<string> Perms(ClaimsPrincipal p) => p.FindAll(AppClaimTypes.Permission).Select(c => c.Value);

    [Fact]
    public void An_unchanged_session_is_left_alone()
    {
        var d = Standard();
        new SessionPermissionRefresher(d, windowsMode: true).Refresh(WindowsUser(d, "SOC-ICs")).Should().BeNull();
    }

    [Fact]
    public void Removing_a_mapping_drops_the_role_and_its_permissions_from_an_open_session()
    {
        var d = Standard();
        var user = WindowsUser(d, "SOC-Analysts", "SOC-ICs");
        Perms(user).Should().Contain("ApproveReports");

        d.Groups.Remove("SOC-ICs");   // an admin removes the SOC-ICs → IncidentCommander mapping
        var refreshed = new SessionPermissionRefresher(d, windowsMode: true).Refresh(user);

        refreshed.Should().NotBeNull();
        refreshed!.IsInRole("IncidentCommander").Should().BeFalse();
        refreshed.IsInRole("Analyst").Should().BeTrue();
        Perms(refreshed).Should().Contain("EditCases").And.NotContain("ApproveReports");
        refreshed.Identity!.Name.Should().Be(@"CORP\jdoe", "identity claims are kept");
        refreshed.FindAll(ClaimTypes.GroupSid).Should().HaveCount(2, "the AD groups themselves are the OS token's, untouched");
    }

    [Fact]
    public void Editing_a_role_updates_its_permissions_in_dev_mode()
    {
        var d = Standard();
        var dev = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Name, "Dev Analyst"), new Claim(ClaimTypes.Role, "Analyst"),
            new Claim(AppClaimTypes.Permission, "ViewCases"), new Claim(AppClaimTypes.Permission, "EditCases"),
        ], "Dev"));

        d.Roles["Analyst"] = [Permission.ViewCases];   // edit rights removed from the role
        var refreshed = new SessionPermissionRefresher(d, windowsMode: false).Refresh(dev);

        Perms(refreshed!).Should().BeEquivalentTo(["ViewCases"]);
        refreshed!.IsInRole("Analyst").Should().BeTrue();
    }

    [Fact]
    public async Task The_provider_publishes_the_change_and_CurrentUser_follows_it()
    {
        var d = Standard();
        var provider = new PermissionRevalidatingAuthStateProvider(
            new SessionPermissionRefresher(d, windowsMode: true), NullLogger<PermissionRevalidatingAuthStateProvider>.Instance);
        provider.SetAuthenticationState(Task.FromResult(new AuthenticationState(WindowsUser(d, "SOC-ICs"))));
        var user = new CurrentUser(new HttpContextAccessor(), provider,
            new ServiceCollection().AddSingleton<IRoleDirectory>(d).BuildServiceProvider());
        user.Has(Permission.ApproveReports).Should().BeTrue();

        d.Groups.Remove("SOC-ICs");
        (await provider.RevalidateAsync()).Should().BeTrue();

        user.Has(Permission.ApproveReports).Should().BeFalse("the circuit's cached principal is dropped on refresh");
        user.Has(Permission.ViewCases).Should().BeFalse("no mapping grants anything any more");
        (await provider.RevalidateAsync()).Should().BeFalse("nothing further changed");
        provider.Dispose();
    }
}
