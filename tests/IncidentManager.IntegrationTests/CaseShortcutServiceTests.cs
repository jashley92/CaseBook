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
/// PROD-20: recent + pinned case shortcuts. Pins round-trip per user; recents derive from the C-05 access
/// log, newest first; and pinning is refused for a case the user can't see.
/// </summary>
public sealed class CaseShortcutServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "analyst-1", RoleSet = [AppRole.SysAdmin] };

    public CaseShortcutServiceTests()
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

    private CaseShortcutService NewService() => new(NewFactory(), _user, _clock);

    private async Task<Guid> SeedCaseAsync(int seq, string title)
    {
        await using var db = NewContext();
        var c = Case.Open(2026, seq, title, title, Classification.Incident, Severity.Medium,
            CaseOrigin.InternalDetection, _user.UserId, _clock.UtcNow);
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return c.Id;
    }

    [Fact]
    public async Task Pins_round_trip_per_user()
    {
        var id = await SeedCaseAsync(1, "Pin me");
        var svc = NewService();

        (await svc.IsPinnedAsync(id)).Should().BeFalse();
        (await svc.TogglePinAsync(id)).Should().BeTrue();
        (await svc.IsPinnedAsync(id)).Should().BeTrue();
        (await svc.PinnedAsync()).Should().ContainSingle().Which.Id.Should().Be(id);

        (await svc.TogglePinAsync(id)).Should().BeFalse();
        (await svc.PinnedAsync()).Should().BeEmpty();
    }

    [Fact]
    public async Task Unpin_is_idempotent(/* BUG-391 */)
    {
        var id = await SeedCaseAsync(1, "Pin me");
        var svc = NewService();
        (await svc.TogglePinAsync(id)).Should().BeTrue();

        await svc.UnpinAsync(id);
        await svc.UnpinAsync(id);   // a double click: stays unpinned (the toggle pinned it again)
        (await svc.IsPinnedAsync(id)).Should().BeFalse();

        await svc.UnpinAsync(Guid.NewGuid());   // never pinned, or not visible: nothing to do
    }

    private CaseShortcutService RacingService(RaceCommandInterceptor race) =>
        new(new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()), race)
            .Options), _user, _clock);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_pin_another_context_removed_first_is_unpinned_without_an_error(bool viaToggle /* BUG-431 */)
    {
        var id = await SeedCaseAsync(1, "Pin me");
        (await NewService().TogglePinAsync(id)).Should().BeTrue();

        // The other tab's unpin deletes the row between this one's read and its delete.
        var race = new RaceCommandInterceptor("DELETE FROM \"PinnedCases\"", "DELETE FROM \"PinnedCases\"");
        var svc = RacingService(race);
        if (viaToggle) (await svc.TogglePinAsync(id)).Should().BeFalse();
        else await svc.UnpinAsync(id);

        race.Ran.Should().BeTrue();
        (await NewService().IsPinnedAsync(id)).Should().BeFalse();
    }

    [Fact]
    public async Task Two_tabs_pinning_at_once_both_end_pinned(/* BUG-431 */)
    {
        var id = await SeedCaseAsync(1, "Pin me");

        // The other tab's pin is saved between this one's read and its insert, so the unique index refuses this one.
        var race = new RaceCommandInterceptor("INSERT INTO \"PinnedCases\"",
            "INSERT INTO \"PinnedCases\" (\"Id\", \"UserId\", \"CaseId\", \"PinnedAtUtc\") VALUES ($id, $user, $case, $at)",
            ("$id", Guid.NewGuid().ToString().ToUpperInvariant()), ("$user", _user.UserId),
            ("$case", id.ToString().ToUpperInvariant()), ("$at", "2026-08-08 00:00:00+00:00"));

        (await RacingService(race).TogglePinAsync(id)).Should().BeTrue();

        race.Ran.Should().BeTrue();
        (await NewService().PinnedAsync()).Should().ContainSingle().Which.Id.Should().Be(id);
    }

    [Fact]
    public async Task Recent_lists_opened_cases_newest_first()
    {
        var a = await SeedCaseAsync(1, "Case A");
        var b = await SeedCaseAsync(2, "Case B");

        await using (var db = NewContext())
        {
            // A opened earlier, B more recently.
            db.CaseAccessEvents.Add(CaseAccessEvent.Start(_user.UserId, a, "2026-001", AccessType.CaseOpen,
                null, null, false, _clock.UtcNow.AddMinutes(-10)));
            db.CaseAccessEvents.Add(CaseAccessEvent.Start(_user.UserId, b, "2026-002", AccessType.CaseOpen,
                null, null, false, _clock.UtcNow));
            await db.SaveChangesAsync();
        }

        var recent = await NewService().RecentAsync(5);
        recent.Select(c => c.Id).Should().Equal(b, a); // newest first
    }

    [Fact]
    public async Task Pinning_a_case_the_user_cannot_see_is_refused()
    {
        await using (var _ = NewContext()) { } // materialise the schema (this test seeds no case)

        var svc = NewService();
        var act = () => svc.TogglePinAsync(Guid.NewGuid());
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    public void Dispose() => _connection.Dispose();
}
