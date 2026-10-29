using FluentAssertions;
using IncidentManager.Application.Preferences;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Local time became the default (LocalTimeByDefault), so the upgrade moves every account on UTC to local time and marks it to be
/// told once; accounts already on local time are left alone and aren't told anything.
/// </summary>
public sealed class LocalTimeByDefaultMigrationTests : IDisposable
{
    private const string Before = "20261023170632_TimelineEntryFormerScreenshots";
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 29, 9, 0, 0, TimeSpan.Zero));

    public LocalTimeByDefaultMigrationTests() => _connection.Open();

    private AppDbContext NewContext() =>
        new(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options);

    private UserDisplayPreferenceService Service(string userId) =>
        new(new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options),
            new TestCurrentUser { UserId = userId }, _clock);

    [Fact]
    public async Task Accounts_on_UTC_move_to_local_time_and_are_told_once()
    {
        await using (var db = NewContext())
        {
            await db.GetService<IMigrator>().MigrateAsync(Before);
            foreach (var (user, local) in new[] { ("on-utc", 0), ("on-local", 1) })
                await db.Database.ExecuteSqlRawAsync(
                    "INSERT INTO UserDisplayPreferences (Id, UserId, DarkTheme, NavCollapsed, LocalTime, TwelveHourClock, " +
                    "CompactRows, AttackChainOpen, SingleKeyShortcutsOff, UpdatedAtUtc) VALUES ({0}, {1}, 0, 0, {2}, 0, 0, 0, 0, 0)",
                    Guid.NewGuid().ToString().ToUpperInvariant(), user, local);
        }

        await using (var db = NewContext())
            await db.Database.MigrateAsync();

        (await Service("on-utc").GetMineAsync())!.LocalTime.Should().BeTrue();
        (await Service("on-local").GetMineAsync())!.LocalTime.Should().BeTrue();

        (await Service("on-utc").TakeLocalTimeNoticeAsync()).Should().BeTrue("their display changed");
        (await Service("on-utc").TakeLocalTimeNoticeAsync()).Should().BeFalse("it's shown once");
        (await Service("on-local").TakeLocalTimeNoticeAsync()).Should().BeFalse("nothing changed for them");
        (await Service("new-account").TakeLocalTimeNoticeAsync()).Should().BeFalse("a new account gets the tour instead");
    }

    public void Dispose() => _connection.Dispose();
}
