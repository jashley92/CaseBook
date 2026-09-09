using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Exercises the cached AppUser mirror (E-22): self-population via Touch, id→name/email resolution,
/// the assignment-picker listing, and rebuild-from-database — over a real DI graph and shared SQLite.
/// </summary>
public sealed class UserDirectoryTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _sp;
    private readonly TestCurrentUser _user = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 12, 0, 0, 0, TimeSpan.Zero));

    public UserDirectoryTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var services = new ServiceCollection();
        services.AddSingleton<ICurrentUser>(_user);
        services.AddSingleton<IClock>(_clock);
        services.AddSingleton<IHashChainService, HashChainService>();
        services.AddSingleton<ICaseChangeNotifier, CaseChangeNotifier>();
        services.AddScoped<AuditChainInterceptor>();
        services.AddDbContext<AppDbContext>((sp, o) =>
            o.UseSqlite(_connection).AddInterceptors(sp.GetRequiredService<AuditChainInterceptor>()));
        services.AddScoped<IAppDbContext>(sp => sp.GetRequiredService<AppDbContext>());
        services.AddSingleton<IUserDirectory, UserDirectory>();
        _sp = services.BuildServiceProvider();

        using var scope = _sp.CreateScope();
        scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreated();
    }

    // A fresh directory instance shares the database but starts with an empty throttle cache — models a
    // new process, and lets a follow-up Touch actually write rather than being throttled.
    private IUserDirectory NewDirectory() => new UserDirectory(_sp.GetRequiredService<IServiceScopeFactory>());

    [Fact]
    public async Task Touch_inserts_a_user_and_resolves_name_and_email()
    {
        var dir = NewDirectory();
        await dir.TouchAsync("S-1-5-21-7", "Dana Analyst", "dana@insurer.example", "dana@insurer.example", "Analyst");

        dir.Resolve("S-1-5-21-7")!.DisplayName.Should().Be("Dana Analyst");
        dir.DisplayFor("S-1-5-21-7").Should().Be("Dana Analyst");
        dir.EmailFor("S-1-5-21-7").Should().Be("dana@insurer.example");
        dir.All().Should().ContainSingle(u => u.UserId == "S-1-5-21-7");

        using var scope = _sp.CreateScope();
        (await scope.ServiceProvider.GetRequiredService<AppDbContext>().Users.CountAsync()).Should().Be(1);
    }

    [Fact]
    public async Task Touch_is_idempotent_on_the_id_and_refreshes_details()
    {
        await NewDirectory().TouchAsync("sid-1", "Old Name", "u@insurer.example", "u@insurer.example", "Analyst");
        // A separate instance (empty throttle cache) records the change rather than skipping it.
        await NewDirectory().TouchAsync("sid-1", "New Name", "u@insurer.example", "u@insurer.example", "Manager");

        using var scope = _sp.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Users.Count(u => u.Sid == "sid-1").Should().Be(1);
        db.Users.Single(u => u.Sid == "sid-1").DisplayName.Should().Be("New Name");
    }

    [Fact]
    public async Task Touch_ignores_system_and_blank_ids()
    {
        var dir = NewDirectory();
        await dir.TouchAsync("system", "System", null, null, "");
        await dir.TouchAsync("", "Nobody", null, null, "");

        using var scope = _sp.CreateScope();
        (await scope.ServiceProvider.GetRequiredService<AppDbContext>().Users.AnyAsync()).Should().BeFalse();
    }

    [Fact]
    public void DisplayFor_maps_system_and_falls_back_to_the_id_when_unknown()
    {
        var dir = NewDirectory();
        dir.DisplayFor("system").Should().Be("System");
        dir.DisplayFor("unknown-sid").Should().Be("unknown-sid");
        dir.EmailFor("unknown-sid").Should().BeNull();
    }

    [Fact]
    public void Invalidate_loads_existing_users_ordered_by_display_name()
    {
        using (var scope = _sp.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Users.AddRange(
                new AppUser { Sid = "z1", DisplayName = "Zoe Zephyr", Email = "z@insurer.example", RolesCsv = "Analyst", LastSeenUtc = _clock.UtcNow },
                new AppUser { Sid = "a1", DisplayName = "Ada Archer", Email = "a@insurer.example", RolesCsv = "Manager", LastSeenUtc = _clock.UtcNow });
            db.SaveChanges();
        }

        var dir = NewDirectory(); // Invalidate runs in the constructor.
        dir.All().Select(u => u.DisplayName).Should().ContainInOrder("Ada Archer", "Zoe Zephyr");
    }

    public void Dispose()
    {
        _sp.Dispose();
        _connection.Dispose();
    }
}
