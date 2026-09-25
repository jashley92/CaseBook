using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
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
/// F-21: the write-authorization backstop asserted inside <see cref="CaseService"/> mutations. Behind the
/// Blazor UI gates, but the guarantee any future non-UI caller inherits: a user who can see a case may still
/// only perform actions their permissions allow. Data scoping (who can see a case) is covered elsewhere;
/// this is about who can <em>write</em>. The acting role is flipped between calls — the service reads the
/// live permission set — so one case can be created by an editor and then probed by a lesser role.
/// </summary>
public sealed class CaseActionAuthorizationTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public CaseActionAuthorizationTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private CaseService NewService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());


    private async Task<Guid> CreateIncidentAsync(CaseService svc)
    {
        var c = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Authz", Title = "Authz case",
            Classification = Classification.Incident, Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        });
        return c.Id;
    }

    [Fact]
    public async Task An_analyst_can_create_note_and_reclassify_but_not_hold_or_archive()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        _user.RoleSet = [AppRole.Analyst]; // ViewCases + EditCases + ChangeClassification

        // EditCases + ChangeClassification actions succeed (the stage gate, not the role, governs the promotion).
        var id = await CreateIncidentAsync(svc);
        await svc.AddNoteAsync(id, "An analyst note.");
        var reclassify = () => svc.ReclassifyAsync(id, Classification.Breach, "NPI confirmed across the estate.");
        await reclassify.Should().NotThrowAsync();

        // ManageLegal is not held → legal hold refused.
        var hold = () => svc.SetLegalHoldAsync(id, held: true);
        (await hold.Should().ThrowAsync<ForbiddenException>())
            .Which.Required.Should().Be(Permission.ManageLegal);

        // Administer is not held → archive refused.
        var archive = () => svc.SetArchivedAsync(id, archived: true);
        (await archive.Should().ThrowAsync<ForbiddenException>())
            .Which.Required.Should().Be(Permission.Administer);
    }

    [Fact]
    public async Task A_viewer_without_edit_cannot_create_a_case()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        _user.RoleSet = [AppRole.Manager]; // ViewCases + ViewAllCases, no EditCases

        var create = () => CreateIncidentAsync(svc);
        (await create.Should().ThrowAsync<ForbiddenException>())
            .Which.Required.Should().Be(Permission.EditCases);
    }

    [Fact]
    public async Task Reclassification_is_refused_for_a_role_lacking_ChangeClassification()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        // Create as an editor, then act as Legal/Privacy: sees the case (ViewAllCases) but holds no
        // ChangeClassification, so the reclassification is refused at the service boundary.
        _user.RoleSet = [AppRole.SysAdmin];
        var id = await CreateIncidentAsync(svc);

        _user.RoleSet = [AppRole.LegalPrivacy];
        var reclassify = () => svc.ReclassifyAsync(id, Classification.Breach, "NPI confirmed across the estate.");
        (await reclassify.Should().ThrowAsync<ForbiddenException>())
            .Which.Required.Should().Be(Permission.ChangeClassification);
    }

    [Fact]
    public async Task An_administrator_may_perform_every_gated_action()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        _user.RoleSet = [AppRole.SysAdmin]; // holds every permission

        var id = await CreateIncidentAsync(svc);
        var reclassify = () => svc.ReclassifyAsync(id, Classification.Breach, "NPI confirmed across the estate.");
        var hold = () => svc.SetLegalHoldAsync(id, held: true);
        var archive = () => svc.SetArchivedAsync(id, archived: true);

        await reclassify.Should().NotThrowAsync();
        await hold.Should().NotThrowAsync();
        // Archiving is refused while a hold is in force (domain rule), so release first, then archive.
        await svc.SetLegalHoldAsync(id, held: false, reason: "Matter settled");
        await archive.Should().NotThrowAsync();
    }

    public void Dispose() => _connection.Dispose();
}
