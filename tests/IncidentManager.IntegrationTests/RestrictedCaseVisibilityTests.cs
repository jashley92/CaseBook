using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
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
/// F-22: <see cref="Permission.ViewRestricted"/> is now enforced by the need-to-know gate
/// (<c>CaseQueryExtensions.ForUser</c>), not merely declared and displayed. A holder (e.g. an Incident
/// Commander, who carries ViewRestricted but not ViewAllCases) may open a restricted case they neither
/// command nor are assigned to; a plain analyst still cannot; ViewAllCases still sees everything.
/// </summary>
public sealed class RestrictedCaseVisibilityTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public RestrictedCaseVisibilityTests()
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

    private CaseService NewService() =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());


    private async Task<Guid> SeedRestrictedCaseOwnedByAnotherAsync()
    {
        await using var db = NewContext();
        var c = Case.Open(2026, 99, "Restricted", "Restricted matter",
            Classification.Breach, Severity.High, CaseOrigin.InternalDetection, "someone-else", _clock.UtcNow);
        c.IsRestricted = true; // the acting user is neither its IC nor an assignee
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return c.Id;
    }

    [Fact]
    public async Task An_incident_commander_holding_ViewRestricted_can_open_a_restricted_case_they_are_not_on()
    {
        var id = await SeedRestrictedCaseOwnedByAnotherAsync();

        // IncidentCommander holds ViewRestricted but NOT ViewAllCases.
        _user.UserId = "ic-unrelated";
        _user.RoleSet = [AppRole.IncidentCommander];

        var svc = NewService();
        var detail = await svc.GetDetailAsync(id);
        detail.Should().NotBeNull();
        (await svc.CanViewAsync(detail!.CaseNumber)).Should().BeTrue();
    }

    [Fact]
    public async Task A_plain_analyst_without_ViewRestricted_still_cannot_open_it()
    {
        var id = await SeedRestrictedCaseOwnedByAnotherAsync();

        _user.UserId = "analyst-unrelated";
        _user.RoleSet = [AppRole.Analyst]; // no ViewRestricted / ViewAllCases

        var svc = NewService();
        (await svc.GetDetailAsync(id)).Should().BeNull();
    }

    [Fact]
    public async Task ViewAllCases_still_sees_a_restricted_case()
    {
        var id = await SeedRestrictedCaseOwnedByAnotherAsync();

        _user.UserId = "mgr";
        _user.RoleSet = [AppRole.Manager]; // ViewAllCases

        var svc = NewService();
        (await svc.GetDetailAsync(id)).Should().NotBeNull();
    }

    public void Dispose() => _connection.Dispose();
}
