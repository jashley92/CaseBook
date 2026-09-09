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

public sealed class ImpactAssessmentPersistenceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 11, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public ImpactAssessmentPersistenceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.Manager];
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
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private sealed class NoOpCaseNotifications : IncidentManager.Application.Abstractions.ICaseNotifications
    {
        public Task OnReclassifiedAsync(IncidentManager.Domain.Entities.Case c, Classification? from, Classification to, CancellationToken ct = default)
            => Task.CompletedTask;
    }

    [Fact]
    public async Task Impact_assessment_persists_and_round_trips()
    {
        Guid id;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var created = await svc.CreateAsync(new CreateCaseRequest
            {
                DescriptiveName = "Breach",
                Title = "Vendor breach",
                Classification = Classification.Breach,
                Severity = Severity.High,
                Origin = CaseOrigin.InternalDetection
            });
            id = created.Id;

            await svc.UpdateImpactAssessmentAsync(id, 2500,
                new[] { "Name", "SocialSecurityNumber", "ClaimsData" },
                "NY, NJ");
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var loaded = await svc.GetDetailAsync(id);

            loaded.Should().NotBeNull();
            loaded!.AffectedIndividualsCount.Should().Be(2500);
            loaded.DataElements.Select(d => d.ElementKey).Should().BeEquivalentTo(
                new[] { "Name", "SocialSecurityNumber", "ClaimsData" });
            loaded.AffectedStates.Should().Be("NY,NJ");
        }
    }

    public void Dispose() => _connection.Dispose();
}
