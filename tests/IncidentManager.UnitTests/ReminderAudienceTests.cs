using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.ApiTokens;
using IncidentManager.Application.Notifications;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>BUG-377: reminders go only to people still entitled to the case: active, ViewCases, and cleared when restricted.</summary>
public class ReminderAudienceTests
{
    internal sealed class Roles : IRoleDirectory
    {
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames)
        {
            var set = new HashSet<Permission>();
            foreach (var r in roleNames)
            {
                if (r == "Analyst") set.Add(Permission.ViewCases);
                if (r == "Cleared") { set.Add(Permission.ViewCases); set.Add(Permission.ViewRestricted); }
                if (r == "Reports") set.Add(Permission.ApproveReports);   // a role without ViewCases
            }
            return set;
        }
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) => new HashSet<string>();
        public void Invalidate() { }
    }

    internal sealed class Users(params UserSummary[] all) : IUserDirectory
    {
        public UserSummary? Resolve(string userId) => all.FirstOrDefault(u => string.Equals(u.UserId, userId, StringComparison.OrdinalIgnoreCase));
        public IReadOnlyList<UserSummary> All() => all;
        public string DisplayFor(string? userId) => userId ?? "";
        public string? EmailFor(string userId) => Resolve(userId) is null ? null : $"{userId}@x.test";
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public void Invalidate() { }
    }

    private sealed class Ad(Func<string, OwnerAccess?> answer) : ITokenOwnerCheck
    {
        public Task<OwnerAccess?> CheckAsync(string ownerUserId, CancellationToken ct = default) => Task.FromResult(answer(ownerUserId));
    }

    private static readonly Users Mirror = new(
        new("analyst", "Analyst", null, null, "Analyst"),
        new("moved", "Moved", null, null, "Reports"),
        new("leaver", "Leaver", null, null, ""),
        new("cleared", "Cleared", null, null, "Cleared"));

    [Theory]
    [InlineData("analyst", true)]
    [InlineData("moved", false)]      // a role that doesn't grant ViewCases
    [InlineData("leaver", false)]     // no role at all
    [InlineData("stranger", false)]   // not in the mirror
    public async Task Only_a_role_granting_ViewCases_is_entitled(string user, bool expected) =>
        (await new ReminderAudience(Mirror, new Roles()).EntitledAsync(user)).Should().Be(expected);

    [Fact]
    public async Task On_a_restricted_case_a_teammate_needs_ViewCases_and_an_outsider_clearance()
    {
        var audience = new ReminderAudience(Mirror, new Roles());
        (await audience.CanSeeAsync("analyst", true, "ic", ["analyst"])).Should().BeTrue();
        (await audience.CanSeeAsync("moved", true, "ic", ["moved"])).Should().BeFalse("on the team, but no longer sees cases");
        (await audience.CanSeeAsync("analyst", true, "ic", [])).Should().BeFalse();
        (await audience.CanSeeAsync("cleared", true, "ic", [])).Should().BeTrue();
    }

    [Fact]
    public async Task The_directory_of_record_overrides_the_mirror_and_an_unreachable_one_leaves_it_standing()
    {
        var ad = new Ad(id => id switch
        {
            "analyst" => new OwnerAccess(false, new HashSet<string> { "Analyst" }),   // disabled since the last sign-in
            "moved" => new OwnerAccess(true, new HashSet<string> { "Analyst" }),      // given ViewCases again
            _ => null,                                                                 // can't say (WF-57)
        });
        var audience = new ReminderAudience(Mirror, new Roles(), ad);
        (await audience.EntitledAsync("analyst")).Should().BeFalse();
        (await audience.EntitledAsync("moved")).Should().BeTrue();
        (await audience.EntitledAsync("cleared")).Should().BeTrue("the directory can't say, so the mirror stands");
    }

    [Fact]
    public async Task A_filtered_owner_falls_to_the_IC_and_a_free_text_owner_is_left_as_written()
    {
        var audience = new ReminderAudience(Mirror, new Roles());
        (await audience.OwnerAsync(false, "analyst", [], "moved")).Should().BeNull();
        (await audience.OwnerAsync(false, "analyst", [], "Vendor contact")).Should().Be("Vendor contact");
        (await audience.IncidentCommanderAsync(false, "leaver", [])).Should().BeNull();
        (await audience.IncidentCommanderAsync(false, "analyst", [])).Should().Be("analyst");
    }

    [Fact]
    public async Task With_nothing_to_ask_the_old_rules_stand()
    {
        var audience = new ReminderAudience(null, null);
        (await audience.EntitledAsync("anyone")).Should().BeTrue();
        (await audience.CanSeeAsync("anyone", true, "ic", ["anyone"])).Should().BeTrue();
        (await audience.CanSeeAsync("anyone", true, "ic", [])).Should().BeFalse("BUG-96: off the team, with no roles to judge by");
    }
}
