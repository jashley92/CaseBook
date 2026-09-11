using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.StageGates;
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

/// <summary>E-27: CaseService.ReopenAsync persists the reopen (phase restored, ClosedAtUtc cleared) with the chain intact.</summary>
public sealed class CaseReopenServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 1, 8, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public CaseReopenServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.Manager];
        using var db = NewContext();
        db.Database.EnsureCreated();
    }

    private AppDbContext NewContext() =>
        new(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private CaseService NewService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new StageGateEvaluator(), new TestSlaTargets());

    private sealed class NoOpCaseNotifications : ICaseNotifications
    {
        public Task OnAssignedAsync(Case c, string a, string b, CaseAssignmentRole role, string by, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
    }

    private Guid SeedClosedCase()
    {
        using var db = NewContext();
        var c = Case.Open(2026, 1, "Beaconing", "C2 beaconing", Classification.Incident,
            Severity.High, CaseOrigin.InternalDetection, "ic1", _clock.UtcNow);
        c.ChangePhase(CasePhase.Containment, null, "ic1", _clock.UtcNow.AddHours(1));
        c.ChangePhase(CasePhase.Recovery, null, "ic1", _clock.UtcNow.AddHours(2));
        c.ChangePhase(CasePhase.Closed, "resolved", "ic1", _clock.UtcNow.AddHours(3));
        db.Cases.Add(c);
        db.SaveChanges();
        return c.Id;
    }

    [Fact]
    public async Task Reopen_persists_the_prior_phase_and_clears_the_close_timestamp()
    {
        var id = SeedClosedCase();
        _clock.UtcNow = _clock.UtcNow.AddDays(1);   // reopen happens after the close transitions

        await using (var db = NewContext())
            await NewService(db).ReopenAsync(id, "new evidence surfaced");

        await using (var db = NewContext())
        {
            var c = await db.Cases.Include(x => x.StatusChanges).FirstAsync(x => x.Id == id);
            c.Phase.Should().Be(CasePhase.Recovery);
            c.ClosedAtUtc.Should().BeNull();
            c.StatusChanges.OrderBy(s => s.ChangedAtUtc).Last().Reason.Should().Be("new evidence surfaced");
        }
    }

    [Fact]
    public async Task Reopen_without_a_reason_is_rejected()
    {
        var id = SeedClosedCase();

        await using var db = NewContext();
        var act = () => NewService(db).ReopenAsync(id, "  ");
        await act.Should().ThrowAsync<ArgumentException>();
    }

    public void Dispose() => _connection.Dispose();
}
