using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
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
/// FR-22: the inline availability check behind intake's Advanced case-number field and the workspace
/// renumber input. Uniqueness is global (unscoped), a blank number is "available" (it auto-generates), and
/// the case being renumbered is excluded from its own check.
/// </summary>
public sealed class CaseNumberAvailabilityTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public CaseNumberAvailabilityTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin];
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


    private async Task<CaseService> WithCaseAsync(string caseNumber)
    {
        await using var db = NewContext();
        var svc = NewService(db);
        await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Avail",
            Title = "Availability case",
            CaseNumber = caseNumber,
            Classification = Classification.Incident,
            Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        });
        return svc;
    }

    [Fact]
    public async Task A_taken_number_is_unavailable_and_a_free_one_is_available()
    {
        var svc = await WithCaseAsync("2026-05_Taken");

        (await svc.IsCaseNumberAvailableAsync("2026-05_Taken")).Should().BeFalse();
        (await svc.IsCaseNumberAvailableAsync("2026-06_Free")).Should().BeTrue();
    }

    [Fact]
    public async Task A_blank_number_is_available_and_an_overlong_one_is_not()
    {
        var svc = await WithCaseAsync("2026-07_Anchor");

        (await svc.IsCaseNumberAvailableAsync(null)).Should().BeTrue();
        (await svc.IsCaseNumberAvailableAsync("   ")).Should().BeTrue();
        (await svc.IsCaseNumberAvailableAsync(new string('x', 201))).Should().BeFalse();
    }

    [Fact]
    public async Task The_renumbered_case_is_excluded_from_its_own_check()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var created = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Self", Title = "Self case", CaseNumber = "2026-08_Self",
            Classification = Classification.Incident, Severity = Severity.Medium, Origin = CaseOrigin.InternalDetection
        });

        // Without the exclusion the case's own number reads as taken; excluding it frees the number (a no-op rename).
        (await svc.IsCaseNumberAvailableAsync("2026-08_Self")).Should().BeFalse();
        (await svc.IsCaseNumberAvailableAsync("2026-08_Self", exceptCaseId: created.Id)).Should().BeTrue();
    }

    public void Dispose() => _connection.Dispose();
}
