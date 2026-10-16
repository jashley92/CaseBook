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
    private static readonly TimeSpan Short = TimeSpan.FromMilliseconds(150);

    private sealed class Clock : IClock { public DateTimeOffset UtcNow { get; set; } = new(2026, 10, 16, 9, 0, 0, TimeSpan.Zero); }

    /// <summary>Maps by name only, as most installs do.</summary>
    private sealed class ByName : IRoleDirectory
    {
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) =>
            roleNames.Any() ? new HashSet<Permission> { Permission.ViewCases } : new HashSet<Permission>();
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups)
        {
            var roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var g in adGroups)
            {
                if (string.Equals(g, @"CORP\SOC-Managers", StringComparison.OrdinalIgnoreCase)) roles.Add("Manager");
                if (string.Equals(g, @"CORP\SOC-Analysts", StringComparison.OrdinalIgnoreCase)) roles.Add("Analyst");
            }
            return roles;
        }
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
            return sids.ToDictionary(s => s, s => s == Managers ? @"CORP\SOC-Managers" : @"CORP\SOC-Analysts");
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

        // Later the account joins another group, and AD hangs naming it.
        groups.Add(Analysts);
        lsa.Hang = Analysts;
        clock.UtcNow += AdTokenOwnerCheck.Fresh;
        var access = await check.CheckRecipientAsync(@"CORP\mgr");

        access.Should().NotBeNull();
        access!.Roles.Should().Contain("Manager", "a partial answer is AD being unreachable: the last whole answer stands");
    }

    [Fact]
    public async Task With_no_whole_answer_yet_a_recipient_is_not_known_and_a_token_is_refused()
    {
        using var lsa = new Lsa { Hang = Managers };
        var check = new AdTokenOwnerCheck(new ByName(), new Clock(), lookup: _ => new(true, [Managers]),
            sids: new SidNames(lsa.Translate, Short));

        (await check.CheckRecipientAsync(@"CORP\mgr")).Should().BeNull("not known, rather than known to hold no role");
        (await check.CheckAsync(@"CORP\mgr"))!.Active.Should().BeFalse();
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
}
