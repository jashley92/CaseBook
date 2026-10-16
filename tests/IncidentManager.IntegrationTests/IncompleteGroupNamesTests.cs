using System.Security.Claims;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Security;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-575: a group-name translation that timed out (or failed) is a partial answer, not the whole one. Read as whole,
/// a Manager mapped by group name lost the role in the token-owner check: dropped from escalations and the executive
/// report, reminders rerouted to the IC and marked sent, tokens refused.
/// </summary>
public sealed class IncompleteGroupNamesTests
{
    private const string Managers = "S-1-5-21-7-1101";
    private const string Analysts = "S-1-5-21-7-1102";
    private const string ManagersAgain = "S-1-5-21-7-1103";   // the managers group, recreated
    private static readonly TimeSpan Short = TimeSpan.FromMilliseconds(150);

    private sealed class Clock : IClock { public DateTimeOffset UtcNow { get; set; } = new(2026, 10, 16, 9, 0, 0, TimeSpan.Zero); }

    /// <summary>Maps by name only, as most installs do.</summary>
    private sealed class ByName : IRoleDirectory
    {
        public readonly Dictionary<string, string> Mappings = new(StringComparer.OrdinalIgnoreCase)
        {
            [@"CORP\SOC-Managers"] = "Manager",
            [@"CORP\SOC-Analysts"] = "Analyst",
        };
        public readonly Dictionary<string, Permission[]> Grants = new(StringComparer.OrdinalIgnoreCase)
        {
            ["Manager"] = [Permission.ViewCases],
            ["Analyst"] = [Permission.ViewCases],
        };
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) =>
            roleNames.SelectMany(r => Grants.GetValueOrDefault(r) ?? []).ToHashSet();
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) =>
            adGroups.Where(Mappings.ContainsKey).Select(g => Mappings[g]).ToHashSet(StringComparer.OrdinalIgnoreCase);
        public IReadOnlySet<string> RolesMappedByName => Mappings.Values.ToHashSet(StringComparer.OrdinalIgnoreCase);
        public bool IsRole(string name) => name is "Manager" or "Analyst";
        public void Invalidate() { }
    }

    /// <summary>The directory: names a SID unless it's told to hang or fail on it.</summary>
    private sealed class Lsa : IDisposable
    {
        public readonly ManualResetEventSlim Release = new();
        public volatile string? Hang;
        public volatile string? Fail;
        public IReadOnlyDictionary<string, string> Translate(IReadOnlyList<string> sids)
        {
            if (Fail is { } f && sids.Contains(f)) throw new InvalidOperationException("RPC server unavailable");
            if (Hang is { } h && sids.Contains(h)) Release.Wait(TimeSpan.FromSeconds(30));
            return sids.ToDictionary(s => s, s => s is Managers or ManagersAgain ? @"CORP\SOC-Managers" : @"CORP\SOC-Analysts");
        }
        public void Dispose() { Release.Set(); Release.Dispose(); }
    }

    [Fact]
    public void A_sid_not_named_in_time_or_whose_translation_failed_is_reported_unanswered()
    {
        using var lsa = new Lsa { Hang = Managers };
        var sids = new SidNames(lsa.Translate, Short);

        var answer = sids.Resolve([Managers, "SOC-Literal"]);
        answer.Complete.Should().BeFalse();
        answer.Unanswered.Should().Equal(Managers);

        lsa.Fail = Analysts;
        var failed = sids.Resolve([Analysts]);
        failed.Complete.Should().BeFalse("a directory that threw gave no answer, not 'no name'");
        sids.Resolve([Analysts]).Unanswered.Should().Equal([Analysts], "and it stays unanswered until it's asked again");
    }

    [Fact]
    public async Task A_sid_the_directory_answered_without_a_name_is_answered()
    {
        var sids = new SidNames(_ => new Dictionary<string, string>(), Short);
        var answer = await sids.ResolveAsync(["S-1-5-21-7-9999"]);
        answer.Complete.Should().BeTrue();
        answer.Names.Should().BeEmpty();
    }

    [Fact]
    public async Task A_token_owner_whose_groups_arent_all_named_keeps_the_last_whole_answer()
    {
        using var lsa = new Lsa();
        var clock = new Clock();
        var groups = new List<string> { Managers };
        var check = new AdTokenOwnerCheck(new ByName(), clock, lookup: _ => new(true, [.. groups]), sids: new SidNames(lsa.Translate, Short));

        (await check.CheckRecipientAsync(@"CORP\mgr"))!.Roles.Should().Equal("Manager");

        // BUG-615: later AD returns the managers group under a SID not named yet (it was recreated), and hangs naming it,
        // so the partial answer maps to no role at all; read as whole, Manager would be lost.
        groups.Clear();
        groups.Add(ManagersAgain);
        lsa.Hang = ManagersAgain;
        clock.UtcNow += AdTokenOwnerCheck.Fresh;
        var access = await check.CheckRecipientAsync(@"CORP\mgr");

        access.Should().NotBeNull();
        access!.Roles.Should().Equal(["Manager"], "a partial answer is AD being unreachable: the last whole answer stands");
        (await check.CheckAsync(@"CORP\mgr"))!.Roles.Should().Equal(["Manager"], "and the token keeps it too");
    }

    [Fact]
    public async Task With_no_whole_answer_yet_a_recipient_is_not_known_and_a_token_gets_only_what_the_named_groups_grant(/* BUG-609 */)
    {
        using var lsa = new Lsa { Hang = Managers };
        var clock = new Clock();
        var sids = new SidNames(lsa.Translate, Short);
        sids.Resolve([Analysts]).Complete.Should().BeTrue("named earlier, for another user");
        var check = new AdTokenOwnerCheck(new ByName(), clock, lookup: _ => new(true, [Managers, Analysts]), sids: sids);

        (await check.CheckRecipientAsync(@"CORP\mgr")).Should().BeNull("not known, rather than known to hold fewer roles");

        var token = await check.CheckAsync(@"CORP\mgr");
        token!.Active.Should().BeTrue("refusing it outright was a regression: it keeps what can be shown");
        token.Roles.Should().Equal(["Analyst"], "never a role the unnamed group might not grant");

        clock.UtcNow += TimeSpan.FromSeconds(10);   // inside the retry wait: the directory isn't asked again
        (await check.CheckAsync(@"CORP\mgr"))!.Roles.Should().Equal(["Analyst"]);
    }

    [Fact]
    public async Task A_disabled_owner_is_refused_even_while_its_groups_arent_named(/* BUG-609 */)
    {
        using var lsa = new Lsa();
        var clock = new Clock();
        var enabled = true;
        var check = new AdTokenOwnerCheck(new ByName(), clock, lookup: _ => new(enabled, enabled ? [Managers] : [ManagersAgain]),
            sids: new SidNames(lsa.Translate, Short));
        (await check.CheckAsync(@"CORP\mgr"))!.Active.Should().BeTrue();

        enabled = false;   // the owner leaves, and AD hangs naming a group
        lsa.Hang = ManagersAgain;
        clock.UtcNow += AdTokenOwnerCheck.Fresh;

        (await check.CheckAsync(@"CORP\mgr"))!.Active.Should().BeFalse("the account is disabled: that's a whole answer");
        (await check.CheckRecipientAsync(@"CORP\mgr"))!.Active.Should().BeFalse();
    }

    [Fact]
    public void An_open_session_keeps_its_roles_while_a_group_isnt_named()
    {
        using var lsa = new Lsa { Hang = Managers };
        var windows = new ClaimsIdentity([new Claim(ClaimTypes.Name, @"CORP\mgr"), new Claim(ClaimTypes.GroupSid, Managers)], "Negotiate");
        var granted = new ClaimsIdentity([new Claim(ClaimTypes.Role, "Manager"), new Claim(AppClaimTypes.Permission, nameof(Permission.ViewCases))]);
        var refresher = new SessionPermissionRefresher(() => new ByName(), windowsMode: true, new SidNames(lsa.Translate, Short));

        refresher.Refresh(new ClaimsPrincipal([windows, granted])).Should().BeNull("nothing is taken away on a partial answer");
    }

    private static ClaimsPrincipal ManagerSession(params string[] groupSids) => new(
    [
        new ClaimsIdentity([new Claim(ClaimTypes.Name, @"CORP\mgr"), .. groupSids.Select(s => new Claim(ClaimTypes.GroupSid, s))], "Negotiate"),
        new ClaimsIdentity([new Claim(ClaimTypes.Role, "Manager"), new Claim(AppClaimTypes.Permission, nameof(Permission.ViewCases))]),
    ]);

    private static string[] Roles(ClaimsPrincipal p) =>
        p.FindAll(ClaimTypes.Role).Select(c => c.Value).Where(v => v is "Manager" or "Analyst").Order().ToArray();

    [Fact]
    public async Task A_role_whose_mapping_was_removed_is_taken_from_an_open_session_while_a_group_isnt_named(/* BUG-609 */)
    {
        using var lsa = new Lsa { Hang = Managers };
        var directory = new ByName();
        var refresher = new SessionPermissionRefresher(() => directory, windowsMode: true, new SidNames(lsa.Translate, Short));

        directory.Mappings.Remove(@"CORP\SOC-Managers");   // an admin revokes it during an AD outage
        var refreshed = await refresher.RefreshAsync(ManagerSession(Managers));

        refreshed.Should().NotBeNull("no mapping grants Manager any more, whatever the group's name turns out to be");
        Roles(refreshed!).Should().BeEmpty();
        refreshed!.HasClaim(AppClaimTypes.Permission, nameof(Permission.ViewCases)).Should().BeFalse();
    }

    [Fact]
    public void A_kept_roles_permission_changes_reach_an_open_session_while_a_group_isnt_named(/* BUG-609 */)
    {
        using var lsa = new Lsa { Hang = Managers };
        var directory = new ByName();
        var refresher = new SessionPermissionRefresher(() => directory, windowsMode: true, new SidNames(lsa.Translate, Short));

        directory.Grants["Manager"] = [Permission.ViewCases, Permission.EditCases];
        var refreshed = refresher.Refresh(ManagerSession(Managers));

        refreshed.Should().NotBeNull();
        Roles(refreshed!).Should().Equal("Manager");
        refreshed!.HasClaim(AppClaimTypes.Permission, nameof(Permission.EditCases)).Should().BeTrue();

        directory.Grants["Manager"] = [];   // and taken away again
        Roles(refresher.Refresh(refreshed)!).Should().Equal("Manager");
        refresher.Refresh(refreshed)!.HasClaim(AppClaimTypes.Permission, nameof(Permission.ViewCases)).Should().BeFalse();
    }

    [Fact]
    public void A_partial_answer_never_adds_a_role(/* BUG-609 */)
    {
        using var lsa = new Lsa { Hang = Managers };
        var directory = new ByName();
        var refresher = new SessionPermissionRefresher(() => directory, windowsMode: true, new SidNames(lsa.Translate, Short));

        // Analysts is named, so the partial answer grants Analyst; the session doesn't hold it.
        var refreshed = refresher.Refresh(ManagerSession(Managers, Analysts));

        (refreshed is null ? ["Manager"] : Roles(refreshed)).Should().Equal(["Manager"], "a role is added only on a whole answer");
    }
}
