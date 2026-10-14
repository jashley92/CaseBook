using FluentAssertions;
using IncidentManager.Application.Preferences;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>Display preferences follow the account: one row per user, stored outside the tamper-evident audit chain.</summary>
public sealed class UserDisplayPreferenceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 28, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public UserDisplayPreferenceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = NewContext();
        db.Database.EnsureCreated();
    }

    private AppDbContext NewContext() => new(new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(new HashChainService(), _user, _clock, new CaseChangeNotifier()))
        .Options);

    private UserDisplayPreferenceService NewService(TestCurrentUser user) =>
        new(new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(new HashChainService(), user, _clock, new CaseChangeNotifier()))
            .Options), user, _clock);

    [Fact]
    public async Task Preferences_are_saved_per_account_and_kept_out_of_the_audit_chain()
    {
        var svc = NewService(_user);
        (await svc.GetMineAsync()).Should().BeNull("nothing is saved until the first change");

        await svc.SaveMineAsync(new DisplayPrefs(DarkTheme: true, NavCollapsed: true, LocalTime: false, TwelveHourClock: false, CompactRows: true));
        await svc.SaveMineAsync(new DisplayPrefs(DarkTheme: true, NavCollapsed: false, LocalTime: true, TwelveHourClock: false, CompactRows: true));

        (await svc.GetMineAsync()).Should().Be(new DisplayPrefs(true, false, true, false, true));
        await using var db = NewContext();
        (await db.UserDisplayPreferences.CountAsync()).Should().Be(1);
        (await db.AuditLog.CountAsync()).Should().Be(0, "a display preference isn't case data");

        // Another person's preferences are their own.
        var colleague = new TestCurrentUser { UserId = "analyst2" };
        (await NewService(colleague).GetMineAsync()).Should().BeNull();
    }

    [Fact]
    public async Task Nothing_is_read_or_written_for_a_signed_out_caller()
    {
        var anon = new TestCurrentUser { IsAuthenticated = false };
        var svc = NewService(anon);
        await svc.SaveMineAsync(new DisplayPrefs(true, true, true, true, true));
        (await svc.GetMineAsync()).Should().BeNull();
        await using var db = NewContext();
        (await db.UserDisplayPreferences.CountAsync()).Should().Be(0);
    }

    [Fact]
    public async Task The_attack_chain_stays_folded_until_the_user_opens_it_and_the_browser_sync_keeps_their_choice()
    {
        var svc = NewService(_user);
        (await svc.GetAttackChainOpenAsync()).Should().BeFalse("it's a one-line strip by default");

        await svc.SetAttackChainOpenAsync(true);
        (await svc.GetAttackChainOpenAsync()).Should().BeTrue();

        // INV-26: the browser's display-settings sync doesn't know about it, so it mustn't reset it.
        await svc.SaveMineAsync(new DisplayPrefs(true, false, false, false, false));
        (await svc.GetAttackChainOpenAsync()).Should().BeTrue();
        (await NewService(new TestCurrentUser { UserId = "analyst2" }).GetAttackChainOpenAsync()).Should().BeFalse();
    }

    [Fact]
    public async Task A_second_tab_that_loses_the_first_insert_race_updates_the_row_the_first_tab_added(/* BUG-368 */)
    {
        // The other tab's insert lands after this one found no row but before its own insert reaches the unique index.
        var racer = new BeforeFirstSave(async () =>
        {
            await using var other = NewContext();
            other.UserDisplayPreferences.Add(new IncidentManager.Domain.Entities.UserDisplayPreference
                { UserId = _user.UserId, DarkTheme = true, UpdatedAtUtc = _clock.UtcNow });
            await other.SaveChangesAsync();
        });
        UserDisplayPreferenceService Racing() => new(new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(racer, new AuditChainInterceptor(new HashChainService(), _user, _clock, new CaseChangeNotifier()))
            .Options), _user, _clock);

        await Racing().SaveMineAsync(new DisplayPrefs(DarkTheme: true, NavCollapsed: true, LocalTime: false, TwelveHourClock: false, CompactRows: true));
        await Racing().SetAttackChainOpenAsync(true);   // the racer has run; the row exists now

        await using var db = NewContext();
        var row = await db.UserDisplayPreferences.SingleAsync();
        row.NavCollapsed.Should().BeTrue("the losing save is applied to the winner's row, not dropped");
        row.CompactRows.Should().BeTrue();
        row.AttackChainOpen.Should().BeTrue();
    }

    [Fact]
    public async Task The_keymap_and_attack_chain_saves_also_survive_a_lost_insert_race(/* BUG-368 */)
    {
        var racer = new BeforeFirstSave(async () =>
        {
            await using var other = NewContext();
            other.UserDisplayPreferences.Add(new IncidentManager.Domain.Entities.UserDisplayPreference
                { UserId = _user.UserId, UpdatedAtUtc = _clock.UtcNow });
            await other.SaveChangesAsync();
        });
        UserDisplayPreferenceService Racing() => new(new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(racer, new AuditChainInterceptor(new HashChainService(), _user, _clock, new CaseChangeNotifier()))
            .Options), _user, _clock);

        await Racing().SetAttackChainOpenAsync(true);
        (await NewService(_user).GetAttackChainOpenAsync()).Should().BeTrue();

        await using (var db = NewContext()) { db.UserDisplayPreferences.RemoveRange(db.UserDisplayPreferences); await db.SaveChangesAsync(); }
        racer.Reset();
        await Racing().SaveKeymapAsync(true, new Dictionary<string, string>());
        (await NewService(_user).GetKeymapAsync()).SingleKeysOff.Should().BeTrue();
    }

    /// <summary>Runs another save once, in the middle of the first save made through these options.</summary>
    private sealed class BeforeFirstSave(Func<Task> during) : Microsoft.EntityFrameworkCore.Diagnostics.SaveChangesInterceptor
    {
        private bool _done;

        public void Reset() => _done = false;

        public override async ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int>> SavingChangesAsync(
            Microsoft.EntityFrameworkCore.Diagnostics.DbContextEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (!_done)
            {
                _done = true;
                await during();
            }
            return result;
        }
    }

    public void Dispose() => _connection.Dispose();
}
