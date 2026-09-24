using FluentAssertions;
using IncidentManager.Application.Work;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Agenda;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// S-12: a feed link is stable until the user resets it; a reset voids that user's earlier links only; a link lapses
/// after a year; and it stops working once its owner holds no CaseBook role.
/// </summary>
public sealed class AgendaFeedServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 24, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "u1" };
    private readonly AgendaFeedTokenService _tokens = new(new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?> { ["Agenda:FeedKey"] = "test-feed-key" }).Build());

    public AgendaFeedServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = NewContext();
        db.Users.AddRange(
            new AppUser { Sid = "u1", DisplayName = "One", RolesCsv = "Analyst", LastSeenUtc = _clock.UtcNow },
            new AppUser { Sid = "u2", DisplayName = "Two", RolesCsv = "Analyst", LastSeenUtc = _clock.UtcNow });
        db.SaveChanges();
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

    private AgendaFeedService Svc() => new(new TestDbContextFactory(Options()), _tokens, _user, _clock);

    private async Task<string> LinkFor(string userId)
    {
        _user.UserId = userId;
        return (await Svc().GetMyLinkAsync())!.Token;
    }

    [Fact]
    public async Task A_link_is_stable_and_resolves_to_its_owner()
    {
        var first = await LinkFor("u1");
        _clock.UtcNow = _clock.UtcNow.AddDays(3);

        (await LinkFor("u1")).Should().Be(first, "the subscribed URL must not change on every visit");
        (await Svc().ResolveAsync(first)).Should().Be("u1");
    }

    [Fact]
    public async Task Resetting_voids_that_users_earlier_links_only()
    {
        var mine = await LinkFor("u1");
        var theirs = await LinkFor("u2");
        _clock.UtcNow = _clock.UtcNow.AddMinutes(5);

        _user.UserId = "u1";
        var fresh = (await Svc().ResetMyLinkAsync())!.Token;

        (await Svc().ResolveAsync(mine)).Should().BeNull();
        (await Svc().ResolveAsync(fresh)).Should().Be("u1");
        (await Svc().ResolveAsync(theirs)).Should().Be("u2");
    }

    [Fact]
    public async Task A_link_lapses_after_a_year_and_a_new_one_is_issued()
    {
        var old = await LinkFor("u1");
        _clock.UtcNow = _clock.UtcNow + AgendaFeedService.MaxAge;

        (await Svc().ResolveAsync(old)).Should().BeNull();
        var renewed = await LinkFor("u1");
        renewed.Should().NotBe(old);
        (await Svc().ResolveAsync(renewed)).Should().Be("u1");
    }

    [Fact]
    public async Task A_link_stops_working_when_its_owner_has_no_role()
    {
        var link = await LinkFor("u1");
        await using (var db = NewContext())
        {
            (await db.Users.SingleAsync(u => u.Sid == "u1")).RolesCsv = "";
            await db.SaveChangesAsync();
        }

        (await Svc().ResolveAsync(link)).Should().BeNull();
    }

    [Fact]
    public async Task Garbage_is_rejected()
    {
        (await Svc().ResolveAsync(null)).Should().BeNull();
        (await Svc().ResolveAsync("x.1.y")).Should().BeNull();
    }

    public void Dispose() => _connection.Dispose();
}
