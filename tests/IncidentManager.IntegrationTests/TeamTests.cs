using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Dashboards;
using IncidentManager.Application.Search;
using IncidentManager.Application.Security;
using IncidentManager.Application.Views;
using IncidentManager.Application.Work;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Web.Components.Shared;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-36: an owning team on each case, for routing and filtering only (owner decision, 2026-10-18). Teams are audited
/// reference data; a case's team is in its row hash only when set; it's set at creation and on the case, refused when
/// stale or retired; the Cases list (its URL filter and CSV), Find, Program and Team workload filter by it, always after
/// need-to-know, so a team filter never shows a restricted case; and a saved view can be shared with one team. Runs on
/// SQLite and, when a server is configured, on SQL Server.
/// </summary>
public sealed class TeamTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };
    private readonly CapturingSecurityEventSink _siem = new();
    private readonly ListedUserDirectory _users = new(ListedUserDirectory.User("analyst1", "Analyst"), ListedUserDirectory.User("analyst2", "Analyst"));

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));

    private TeamService Teams(TestDatabase db) => new(db.Factory(), _user, _clock, _siem);

    private CaseService Cases(TestDatabase db) =>
        new(db.Factory(), _user, _clock, new CaseNumberGenerator(db.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private Task<Case> CaseAsync(CaseService svc, string title, Guid? team = null, Severity severity = Severity.High) =>
        svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = title, Title = title, Classification = Classification.Incident, Severity = severity, TeamId = team,
        });

    private void As(string userId, params AppRole[] roles) => (_user.UserId, _user.RoleSet) = (userId, roles.ToHashSet());

    private static async Task<Case> LoadAsync(TestDatabase db, Guid id)
    {
        await using var ctx = db.NewContext();
        return await ctx.Cases.AsNoTracking().Include(c => c.DataElements).SingleAsync(c => c.Id == id);
    }

    // --- Teams: reference data, audited ---

    [Theory, MemberData(nameof(Providers))]
    public async Task A_team_is_added_changed_retired_and_restored_with_an_audit_trail_and_SIEM_events(string provider)
    {
        using var db = Open(provider);
        var teams = Teams(db);

        var id = await teams.CreateAsync(new TeamEdit("SOC tier 1", null, null, ["analyst1"]));
        var created = (await teams.ListAllAsync()).Single();
        created.Key.Should().Be("SocTier1", "a stable key from the first name");
        created.Members.Should().Equal("analyst1");

        await teams.UpdateAsync(id, new TeamEdit("SOC tier one", "EDR", "https://edr.example/case/{0}", ["analyst2"]), created.Stamp);
        var changed = (await teams.ListAllAsync()).Single();
        (changed.Key, changed.Name, changed.DetectionSourceLabel, changed.DetectionLinkTemplate).Should()
            .Be(("SocTier1", "SOC tier one", "EDR", "https://edr.example/case/{0}"), "renamed, but the key never changes");
        changed.Members.Should().Equal("analyst2");

        await teams.SetActiveAsync(id, false, changed.Stamp);
        var retired = (await teams.ListAllAsync()).Single();
        retired.IsActive.Should().BeFalse();
        await teams.SetActiveAsync(id, true, retired.Stamp);
        (await teams.ListAllAsync()).Single().IsActive.Should().BeTrue();

        await using (var ctx = db.NewContext())
        {
            var trail = await ctx.AuditLog.AsNoTracking().Where(a => a.EntityType == "Team" || a.EntityType == "TeamMember")
                .OrderBy(a => a.Sequence).Select(a => new { a.EntityType, a.Action }).ToListAsync();
            trail.Should().Contain(new { EntityType = "Team", Action = AuditAction.Create });
            trail.Count(t => t.EntityType == "Team" && t.Action == AuditAction.Update).Should().Be(3, "the edit, the retire and the restore");
            trail.Should().Contain(new { EntityType = "TeamMember", Action = AuditAction.Create });
            trail.Should().Contain(new { EntityType = "TeamMember", Action = AuditAction.Delete }, "analyst1 left the team");
            (await ctx.Teams.AsNoTracking().SingleAsync()).RowHash.Should().StartWith(Canonical.V5Prefix, "hash-chained like other reference data");
        }
        var events = _siem.Events.Where(e => e.EventId == SecurityEventIds.ReferenceDataChanged).ToList();
        events.Should().HaveCount(4, "created, changed, retired, restored (5405)");
        events.Should().OnlyContain(e => e.TargetType == ReferenceDataKinds.Team);
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_stale_page_a_taken_name_a_bad_link_and_a_non_administrator_are_refused(string provider)
    {
        using var db = Open(provider);
        var teams = Teams(db);
        var id = await teams.CreateAsync(new TeamEdit("Fraud desk", null, null, []));
        var opened = (await teams.ListAllAsync()).Single();
        await teams.UpdateAsync(id, new TeamEdit("Fraud", null, null, []), opened.Stamp);

        await teams.Invoking(t => t.UpdateAsync(id, new TeamEdit("Fraud team", null, null, []), opened.Stamp))
            .Should().ThrowAsync<StaleEditException>("C9: the page's stamp is the team as it was shown");
        await teams.Invoking(t => t.CreateAsync(new TeamEdit(" FRAUD ", null, null, [])))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("*already a team named*");
        await teams.Invoking(t => t.CreateAsync(new TeamEdit("Hunters", null, "https://edr.example/case", [])))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*{0}*");

        As("analyst1", AppRole.Analyst);
        await teams.Invoking(t => t.CreateAsync(new TeamEdit("Hunters", null, null, []))).Should().ThrowAsync<ForbiddenException>();
        (await teams.ListAsync()).Should().ContainSingle("reads aren't gated: the case pages and filters use them");
    }

    // --- The case's team: in the hash only when set ---

    [Theory, MemberData(nameof(Providers))]
    public async Task A_case_without_a_team_keeps_its_exact_hash_and_one_with_a_team_has_it_covered(string provider)
    {
        using var db = Open(provider);
        var team = await Teams(db).CreateAsync(new TeamEdit("SOC", null, null, []));
        var cases = Cases(db);
        var plain = await LoadAsync(db, (await CaseAsync(cases, "No team")).Id);
        var owned = await LoadAsync(db, (await CaseAsync(cases, "Owned", team)).Id);

        Canonical.InFormat(5, plain.BuildCanonicalContent).Should().Be(Canonical.InFormat(4, plain.BuildCanonicalContent),
            "a case without a team builds what format 4 built, so nothing is re-baselined");
        Canonical.Covers(4, owned.BuildCanonicalContent).Should().BeFalse("a format-4 hash can't show a team");
        _hasher.RowHashMatches(owned, owned.RowHash!).Should().BeTrue();
        owned.SetTeam(null, "dba", _clock.UtcNow);
        _hasher.RowHashMatches(owned, owned.RowHash!).Should().BeFalse("a team taken off in the database is caught");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task The_team_is_set_when_filing_and_changed_on_the_case_and_a_stale_or_retired_one_is_refused(string provider)
    {
        using var db = Open(provider);
        var teams = Teams(db);
        var soc = await teams.CreateAsync(new TeamEdit("SOC", null, null, []));
        var fraud = await teams.CreateAsync(new TeamEdit("Fraud", null, null, []));
        var cases = Cases(db);

        var c = await CaseAsync(cases, "Filed with a team", soc);
        (await LoadAsync(db, c.Id)).TeamId.Should().Be(soc);

        var shown = (await LoadAsync(db, c.Id)).TeamConcurrencyStamp();
        await cases.SetTeamAsync(c.Id, fraud, shown);
        (await LoadAsync(db, c.Id)).TeamId.Should().Be(fraud);
        await cases.Invoking(s => s.SetTeamAsync(c.Id, null, shown)).Should().ThrowAsync<StaleEditException>();

        var fraudView = (await teams.ListAllAsync()).Single(t => t.Id == fraud);
        await teams.SetActiveAsync(soc, false, (await teams.ListAllAsync()).Single(t => t.Id == soc).Stamp);
        await cases.Invoking(s => s.SetTeamAsync(c.Id, soc)).Should().ThrowAsync<InvalidOperationException>().WithMessage("*retired*");
        await cases.Invoking(s => CaseAsync(s, "Onto a retired team", soc)).Should().ThrowAsync<InvalidOperationException>().WithMessage("*retired*");
        (await LoadAsync(db, c.Id)).TeamId.Should().Be(fraudView.Id, "it stays with the team it has");

        await cases.SetTeamAsync(c.Id, null);
        (await LoadAsync(db, c.Id)).TeamId.Should().BeNull();
        await using var ctx = db.NewContext();
        (await ctx.AuditLog.AsNoTracking().CountAsync(a => a.EntityType == "Case" && a.EntityId == c.Id.ToString()
            && a.AfterJson != null && a.AfterJson.Contains("TeamId"))).Should().BeGreaterThanOrEqualTo(2, "each change is in the trail");
    }

    // --- Filters, after need-to-know ---

    private async Task<(Guid Soc, Guid Visible, Guid Restricted, Guid Other, Guid NoTeam)> SeedFilteredAsync(TestDatabase db)
    {
        var teams = Teams(db);
        var soc = await teams.CreateAsync(new TeamEdit("SOC tier 1", null, null, ["analyst1"]));
        var fraud = await teams.CreateAsync(new TeamEdit("Fraud", null, null, []));
        var cases = Cases(db);
        var visible = (await CaseAsync(cases, "Beacon on a laptop", soc)).Id;
        var restricted = (await CaseAsync(cases, "Beacon from an insider", soc)).Id;
        await cases.SetRestrictedAsync(restricted, true, "Insider matter");
        var other = (await CaseAsync(cases, "Beacon in payments", fraud)).Id;
        var noTeam = (await CaseAsync(cases, "Beacon with no team", null, Severity.Low)).Id;
        As("analyst1", AppRole.Analyst);   // on no case, no clearance: the restricted case is outside need-to-know
        return (soc, visible, restricted, other, noTeam);
    }

    private static CaseFilter Parse(params (string Key, string Value)[] q) =>
        CaseListQuery.Parse(k => q.FirstOrDefault(p => p.Key == k).Value);

    [Theory, MemberData(nameof(Providers))]
    public async Task The_cases_list_and_its_csv_filter_by_team_and_never_show_a_restricted_case(string provider)
    {
        using var db = Open(provider);
        var (_, visible, restricted, other, noTeam) = await SeedFilteredAsync(db);
        var cases = Cases(db);

        var page = await cases.ListAsync(Parse(("scope", "all"), ("team", "soctier1")));
        page.Items.Select(i => i.Id).Should().Equal([visible], "the team's cases, read ignoring case; never the restricted one");
        page.Items.Single().TeamId.Should().NotBeNull();
        (await cases.ListAsync(Parse(("team", "none")))).Items.Select(i => i.Id).Should().Equal([noTeam]);
        (await cases.ListAsync(Parse(("team", "NoSuchTeam")))).Items.Should().BeEmpty("a stale link lists nothing, not everything");
        (await cases.ListAsync(Parse())).Items.Select(i => i.Id).Should().BeEquivalentTo([visible, other, noTeam]);

        var (items, _) = await CaseListCsv.CollectAsync(cases, Parse(("team", "SocTier1")));
        var names = (await Teams(db).ListAsync()).ToDictionary(t => t.Id, t => t.Name);
        var csv = CaseListCsv.Build(items, _clock.UtcNow, false, c => c?.ToString() ?? "", p => p.ToString(), s => s.ToString(), _ => "",
            id => id is { } t ? names[t] : "");
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        lines.Should().HaveCount(3, "the comment, the header and the one visible case");
        lines[1].Should().EndWith(",team");
        lines[2].Should().Contain("Beacon on a laptop").And.EndWith(",SOC tier 1");
        csv.Should().NotContain("insider");
        restricted.Should().NotBeEmpty();
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task Find_program_and_team_workload_filter_by_team_after_need_to_know(string provider)
    {
        using var db = Open(provider);
        var (soc, visible, _, _, _) = await SeedFilteredAsync(db);
        var f = db.Factory();

        var found = await new FindService(f, _user, _users).FindAsync("Beacon team:SocTier1");
        found.Cases.Select(c => c.Id).Should().Equal([visible], "Find narrows to the team, after need-to-know");
        found.Filters.Should().Contain("team SocTier1");
        (await new FindService(f, _user, _users).FindAsync("Beacon team:none")).Cases.Should().ContainSingle();
        FindQuery.Parse("team:soc-1").Unread.Should().ContainSingle(u => u.StartsWith("team:soc-1"), "a key is letters and digits");

        var dashboard = new DashboardService(f, _user, _clock, new TestSlaTargets(), new NotifyOff(), new NotificationRuleService(f, _user, _clock));
        (await dashboard.GetAsync(false, false, TeamScope.Of(soc))).OpenCount.Should().Be(1, "the restricted case isn't counted");
        (await dashboard.GetAsync(false, false, TeamScope.NoTeam)).OpenCount.Should().Be(1);
        (await dashboard.GetAsync(false, false, TeamScope.Any)).OpenCount.Should().Be(3);
        (await dashboard.PhaseAgingAsync(false, TeamScope.Of(soc))).Sum(p => p.Count).Should().Be(1);

        var workload = new TeamWorkloadService(f, _user, _clock, new TestSlaTargets());
        (await workload.GetAsync(TeamScope.Of(soc))).TotalOpen.Should().Be(1);
        (await workload.GetAsync(await Teams(db).ScopeAsync("SOCTIER1"))).TotalOpen.Should().Be(1, "the page reads team= as the Cases list does");
        (await workload.GetAsync(TeamScope.Nothing)).TotalOpen.Should().Be(0);
    }

    private sealed class NotifyOff : IncidentManager.Application.Compliance.INotificationDeadlineSettingsProvider
    {
        public IncidentManager.Application.Compliance.NotificationDeadlineSettings Current =>
            IncidentManager.Application.Compliance.NotificationDeadlineSettings.Off;
    }

    // --- Saved views shared with a team ---

    [Theory, MemberData(nameof(Providers))]
    public async Task A_view_shared_with_a_team_is_seen_by_its_members_only(string provider)
    {
        using var db = Open(provider);
        var teams = Teams(db);
        var soc = await teams.CreateAsync(new TeamEdit("SOC", null, null, ["analyst1", "analyst2"]));
        var fraud = await teams.CreateAsync(new TeamEdit("Fraud", null, null, ["analyst3"]));
        SavedViewService Views() => new(db.Factory(), _user, _users, _clock);

        As("analyst1", AppRole.Analyst);
        await Views().SaveAsync("SOC triage", "team=Soc&sla=true", isShared: true, soc);
        await Views().SaveAsync("Everyone's queue", "sla=true", isShared: true);
        await Views().SaveAsync("Mine only", "scope=mine", isShared: false, soc);   // not shared: the team is ignored
        await Views().Invoking(v => v.SaveAsync("Theirs", "q=x", true, fraud)).Should()
            .ThrowAsync<InvalidOperationException>().WithMessage("*team you're in*");

        As("analyst2", AppRole.Analyst);
        var seen = await Views().ListAsync();
        seen.Select(v => v.Name).Should().BeEquivalentTo(["SOC triage", "Everyone's queue"]);
        seen.Single(v => v.Name == "SOC triage").TeamName.Should().Be("SOC");

        As("analyst3", AppRole.Analyst);
        (await Views().ListAsync()).Select(v => v.Name).Should().Equal(["Everyone's queue"], "not in the team: its view isn't listed");

        As("admin1", AppRole.SysAdmin);
        await teams.SetActiveAsync(soc, false, (await teams.ListAllAsync()).Single(t => t.Id == soc).Stamp);
        As("analyst1", AppRole.Analyst);
        await Views().Invoking(v => v.SaveAsync("Late", "q=y", true, soc)).Should().ThrowAsync<InvalidOperationException>("a retired team takes no new view");
    }

    // --- CAP-36 review ---

    [Theory, MemberData(nameof(Providers))]
    public async Task Retiring_a_team_moves_its_stamp_so_an_editor_open_on_it_saves_only_with_the_fresh_one(string provider)
    {
        // The Teams page gives an editor open on the team the stamp its own retire left (AdminTeams.RestampEditor): the
        // stamp it opened with is refused after the retire, and the one the list shows afterwards saves what was typed.
        using var db = Open(provider);
        var teams = Teams(db);
        var id = await teams.CreateAsync(new TeamEdit("Hunters", null, null, ["analyst1"]));
        var opened = (await teams.ListAllAsync()).Single();

        await teams.SetActiveAsync(id, false, opened.Stamp);

        var typed = new TeamEdit("Threat hunters", "EDR", null, ["analyst1", "analyst2"]);
        await teams.Invoking(t => t.UpdateAsync(id, typed, opened.Stamp)).Should().ThrowAsync<StaleEditException>();
        await teams.UpdateAsync(id, typed, (await teams.ListAllAsync()).Single().Stamp);
        var saved = (await teams.ListAllAsync()).Single();
        (saved.Name, saved.IsActive, saved.Members.Count).Should().Be(("Threat hunters", false, 2), "the edit lands; the retire stays");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task Setting_a_case_team_waits_for_a_retire_in_progress_and_then_refuses_the_retired_team(string provider)
    {
        // C1: the active-team check runs inside the gate a retire holds, so it reads the team after the retire, not before.
        using var db = Open(provider);
        var soc = await Teams(db).CreateAsync(new TeamEdit("SOC", null, null, []));
        var cases = Cases(db);
        var c = await CaseAsync(cases, "Racing a retire");

        Task setting;
        var gate = await GuardGate.EnterAsync();   // as SetActiveAsync holds it while it retires
        try
        {
            setting = cases.SetTeamAsync(c.Id, soc);
            await using var ctx = db.NewContext();
            (await ctx.Teams.SingleAsync(t => t.Id == soc)).IsActive = false;
            await ctx.SaveChangesAsync();
        }
        finally { gate.Dispose(); }

        await setting.Invoking(t => t).Should().ThrowAsync<InvalidOperationException>().WithMessage("*retired*");
        (await LoadAsync(db, c.Id)).TeamId.Should().BeNull();
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task Filing_a_case_on_a_team_waits_for_a_retire_in_progress_and_then_refuses_the_retired_team(string provider)
    {
        // CAP-36 review (C1): as SetTeamAsync, the create's active-team check runs with its save, inside the gate a retire
        // holds. Whether the create reaches the gate before or after the retire's write, it reads the team after it (C17).
        using var db = Open(provider);
        var soc = await Teams(db).CreateAsync(new TeamEdit("SOC", null, null, []));
        var cases = Cases(db);

        Task<Case> filing;
        var gate = await GuardGate.EnterAsync();   // as SetActiveAsync holds it while it retires
        try
        {
            filing = CaseAsync(cases, "Racing a retire", soc);
            await using var ctx = db.NewContext();
            (await ctx.Teams.SingleAsync(t => t.Id == soc)).IsActive = false;
            await ctx.SaveChangesAsync();
        }
        finally { gate.Dispose(); }

        await filing.Invoking(t => t).Should().ThrowAsync<InvalidOperationException>().WithMessage("*retired*");
        await using var check = db.NewContext();
        (await check.Cases.CountAsync(c => c.Title == "Racing a retire")).Should().Be(0, "nothing was filed");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task Team_membership_ignores_case_for_sharing_a_view_and_listing_it(string provider)
    {
        // On SQLite "==" is case-sensitive; membership is matched ignoring case everywhere, as the Teams page shows it.
        using var db = Open(provider);
        var soc = await Teams(db).CreateAsync(new TeamEdit("SOC", null, null, ["Analyst1", "ANALYST2"]));
        SavedViewService Views() => new(db.Factory(), _user, _users, _clock);

        As("analyst1", AppRole.Analyst);
        await Views().SaveAsync("SOC triage", "sla=true", isShared: true, soc);
        (await Teams(db).MineAsync()).Select(t => t.Id).Should().Equal([soc]);

        As("analyst2", AppRole.Analyst);
        (await Views().ListAsync()).Select(v => v.Name).Should().Equal(["SOC triage"]);
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task The_improvement_action_register_and_its_csv_filter_by_team_as_the_program_page_links_them(string provider)
    {
        // C15: Program's "Improvement actions" link carries team=; the register reads it as the Cases list does.
        using var db = Open(provider);
        var soc = await Teams(db).CreateAsync(new TeamEdit("SOC", null, null, []));
        var cases = Cases(db);
        var owned = await CaseAsync(cases, "Owned case", soc);
        var unowned = await CaseAsync(cases, "Unowned case");
        var lessons = new IncidentManager.Application.Lessons.LessonsService(db.Factory(), _user, _clock, _users);
        await lessons.AddActionAsync(owned.Id, new("Patch the VPN", "Remote access", null, null, null));
        await lessons.AddActionAsync(unowned.Id, new("Rotate keys", "Secrets", null, null, null));

        async Task<List<string>> Titles(string? team) =>
            (await lessons.GetRegisterAsync(new(Team: await Teams(db).ScopeAsync(team)))).Rows.Select(r => r.Action.Title).ToList();
        (await Titles("SOC")).Should().Equal(["Patch the VPN"]);
        (await Titles("none")).Should().Equal(["Rotate keys"]);
        (await Titles(null)).Should().BeEquivalentTo(["Patch the VPN", "Rotate keys"]);
        (await lessons.ExportRegisterCsvAsync(new(Team: await Teams(db).ScopeAsync("SOC")))).Should().Contain("Patch the VPN").And.NotContain("Rotate keys");
        IncidentManager.Web.Components.Shared.ProgramNav.WithTeam("program/improvement-actions", "SOC").Should().Be("program/improvement-actions?team=SOC");
    }
}
