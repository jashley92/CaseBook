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

    public void Dispose() => _connection.Dispose();
}
