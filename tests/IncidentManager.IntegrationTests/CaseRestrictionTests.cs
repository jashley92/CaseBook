using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// S-08: a case can be restricted to need-to-know (at intake or later) and the restriction lifted. Restricting needs
/// only edit rights and never locks the actor out; lifting is limited to the IC or a cleared role and needs a reason.
/// </summary>
public sealed class CaseRestrictionTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 24, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public CaseRestrictionTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
        .Options;

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
        return db;
    }

    private CaseService NewService() =>
        new(new TestDbContextFactory(Options()), _user, _clock, new CaseNumberGenerator(NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private sealed class NoOpCaseNotifications : ICaseNotifications
    {
        public Task OnAssignedAsync(Case c, string assigneeUserId, string assigneeDisplayName, CaseAssignmentRole role, string assignedByUserId, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
    }

    private async Task<Guid> SeedOpenCaseAsync(string? ic = null)
    {
        await using var db = NewContext();
        var c = Case.Open(2026, 7, "Restrict", "A sensitive matter",
            Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "someone-else", _clock.UtcNow);
        c.IncidentCommander = ic;
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return c.Id;
    }

    private async Task<Case> LoadAsync(Guid id)
    {
        await using var db = NewContext();
        return await db.Cases.Include(c => c.Assignments).AsNoTracking().SingleAsync(c => c.Id == id);
    }

    [Fact]
    public async Task An_analyst_can_restrict_a_case_and_is_added_to_the_team_so_they_keep_access()
    {
        var id = await SeedOpenCaseAsync();
        _user.UserId = "analyst-1";
        _user.RoleSet = [AppRole.Analyst];

        var svc = NewService();
        await svc.SetRestrictedAsync(id, true, "Insider matter");

        var c = await LoadAsync(id);
        c.IsRestricted.Should().BeTrue();
        c.Assignments.Should().ContainSingle(a => a.UserId == "analyst-1" && a.Role == CaseAssignmentRole.Analyst);
        (await svc.GetDetailAsync(id)).Should().NotBeNull("the actor must not lock themselves out");

        // Another analyst who isn't on the case no longer sees it.
        _user.UserId = "analyst-2";
        (await NewService().GetDetailAsync(id)).Should().BeNull();
    }

    [Fact]
    public async Task A_cleared_role_restricting_is_not_added_to_the_team()
    {
        var id = await SeedOpenCaseAsync();
        _user.UserId = "ic-1";
        _user.RoleSet = [AppRole.IncidentCommander]; // holds ViewRestricted

        await NewService().SetRestrictedAsync(id, true, null);

        var c = await LoadAsync(id);
        c.IsRestricted.Should().BeTrue();
        c.Assignments.Should().BeEmpty();
    }

    [Fact]
    public async Task A_case_can_be_opened_restricted_and_the_filer_keeps_access()
    {
        _user.UserId = "analyst-1";
        _user.RoleSet = [AppRole.Analyst];
        var svc = NewService();

        var created = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Insider", Title = "Insider matter", IsRestricted = true
        });

        var c = await LoadAsync(created.Id);
        c.IsRestricted.Should().BeTrue();
        c.Assignments.Should().ContainSingle(a => a.UserId == "analyst-1");
        (await svc.GetDetailAsync(created.Id)).Should().NotBeNull();
    }

    [Fact]
    public async Task An_assigned_analyst_cannot_lift_the_restriction()
    {
        var id = await SeedOpenCaseAsync();
        _user.UserId = "analyst-1";
        _user.RoleSet = [AppRole.Analyst];
        var svc = NewService();
        await svc.SetRestrictedAsync(id, true, null);

        var act = () => svc.SetRestrictedAsync(id, false, "Not sensitive after all");

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*incident commander*");
        (await LoadAsync(id)).IsRestricted.Should().BeTrue();
    }

    [Fact]
    public async Task The_incident_commander_can_lift_it_with_a_reason_that_lands_in_the_audit_trail()
    {
        var id = await SeedOpenCaseAsync(ic: "analyst-ic");
        _user.UserId = "analyst-ic";
        _user.RoleSet = [AppRole.Analyst]; // not cleared, but the case's IC
        var svc = NewService();
        await svc.SetRestrictedAsync(id, true, null);

        var noReason = () => svc.SetRestrictedAsync(id, false, "  ");
        await noReason.Should().ThrowAsync<ArgumentException>();

        await svc.SetRestrictedAsync(id, false, "Counsel cleared it");

        (await LoadAsync(id)).IsRestricted.Should().BeFalse();
        await using var db = NewContext();
        (await db.AuditLog.AsNoTracking().AnyAsync(a => a.Reason == "Counsel cleared it")).Should().BeTrue();
    }

    [Fact]
    public async Task Viewers_without_edit_rights_cannot_restrict()
    {
        var id = await SeedOpenCaseAsync();
        _user.UserId = "manager-1";
        _user.RoleSet = [AppRole.Manager];

        var act = () => NewService().SetRestrictedAsync(id, true, null);

        await act.Should().ThrowAsync<ForbiddenException>();
    }

    [Fact]
    public async Task Clearance_roles_include_custom_roles_granting_ViewRestricted()
    {
        await using (var db = NewContext())
        {
            var custom = new Role { Name = "Insider Response", IsSystem = false };
            custom.SetPermissions([Permission.ViewCases, Permission.ViewRestricted], "admin", _clock.UtcNow);
            var plain = new Role { Name = "Tier 1", IsSystem = false };
            plain.SetPermissions([Permission.ViewCases, Permission.EditCases], "admin", _clock.UtcNow);
            db.Roles.AddRange(custom, plain);
            await db.SaveChangesAsync();
        }

        var roles = await NewService().GetRestrictedClearanceRolesAsync();

        roles.Should().Contain("Insider Response").And.NotContain("Tier 1");
    }

    public void Dispose() => _connection.Dispose();
}
