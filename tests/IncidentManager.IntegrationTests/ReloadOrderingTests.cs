using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Configuration;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Web.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// C21 (BUG-623, BUG-628, BUG-225): an in-memory copy of stored state doesn't take an older read after a newer one. Each
/// test holds one reload after it has read (<see cref="HeldReadInterceptor"/>), changes the data, runs a newer reload, then
/// lets the older one go on: the copy must end up with the newer data. Nothing here depends on which waiter runs first.
/// </summary>
public sealed class ReloadOrderingTests : IDisposable
{
    private static readonly TimeSpan Within = TimeSpan.FromSeconds(10);
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"im-reload-{Guid.NewGuid():N}.db");
    private readonly string _emptyPath = Path.Combine(Path.GetTempPath(), $"im-reload-empty-{Guid.NewGuid():N}.db");
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 16, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };

    public ReloadOrderingTests()
    {
        using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(Conn).Options);
        db.Database.EnsureCreated();
    }

    private string Conn => $"Data Source={_dbPath}";

    private async Task SetAsync(string key, string value)
    {
        var factory = new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(Conn)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);
        await new AdminSettingsService(factory, _user, _clock, new NoOpReloader()).SetAsync(key, value);
    }

    private sealed class NoOpReloader : ISettingsReloader { public void Reload() { } }

    private IConfigurationRoot Settings(string conn, params Microsoft.EntityFrameworkCore.Diagnostics.IInterceptor[] interceptors) =>
        new ConfigurationBuilder().Add(new DbSettingsConfigurationSource("Sqlite", conn, interceptors)).Build();

    [Fact]
    public async Task A_settings_reload_that_read_first_cant_store_last(/* BUG-623 */)
    {
        await SetAsync("Email:From", "first@insurer.example");
        using var held = new HeldReadInterceptor("AppSettings");
        var config = Settings(Conn, held);
        config["Email:From"].Should().Be("first@insurer.example");

        held.Arm();
        var older = Task.Run(config.Reload);
        held.WaitHeld(Within).Should().BeTrue("the older reload has read the first value");
        await SetAsync("Email:From", "second@insurer.example");
        var newer = Task.Run(config.Reload);
        // Unordered, the newer reload stores now and the older one after it. Ordered, it waits for the older one.
        await Task.WhenAny(newer, Task.Delay(500));
        held.Release();
        await Task.WhenAll(older, newer);

        config["Email:From"].Should().Be("second@insurer.example", "the value saved last is the one in effect");
    }

    [Fact]
    public async Task A_reload_reports_its_own_error_not_another_reloads(/* BUG-623 */)
    {
        await SetAsync("Email:From", "soc@insurer.example");
        var broken = Settings($"Data Source={_emptyPath}");   // no AppSettings table: every load fails
        var healthy = Settings(Conn);
        var brokenReloader = new ConfigurationReloader(broken);
        var healthyReloader = new ConfigurationReloader(healthy);
        string? healthyError = "not run";
        Task? other = null;
        // Between the failing reload's load and its reading of the error, a healthy reload runs (unless it has to wait).
        using var hook = ChangeToken.OnChange(broken.GetReloadToken, () =>
        {
            other ??= Task.Run(() => healthyError = healthyReloader.ReloadAndReport());
            other.Wait(TimeSpan.FromMilliseconds(500));
        });

        var error = brokenReloader.ReloadAndReport();
        other.Should().NotBeNull("the failing reload raised its change");
        if (other is not null) await other;

        error.Should().NotBeNull("its own load failed, whatever the other reload did meanwhile");
        healthyError.Should().BeNull();
    }

    [Fact]
    public async Task A_role_directory_reload_that_read_first_cant_store_last(/* BUG-225 */)
    {
        using var held = new HeldReadInterceptor("AdGroupRoleMappings");
        await using var services = new ServiceCollection()
            .AddDbContext<AppDbContext>(o => o.UseSqlite(Conn).AddInterceptors(held)).BuildServiceProvider();
        using (var scope = services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.RoleMappings.Add(new AdGroupRoleMapping { AdGroup = @"CORP\SOC", RoleName = "Analyst", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
            await db.SaveChangesAsync();
        }
        var directory = new RoleDirectory(services.GetRequiredService<IServiceScopeFactory>());
        directory.RolesForGroups([@"CORP\SOC"]).Should().Equal("Analyst");

        held.Arm();
        var older = Task.Run(directory.Invalidate);
        held.WaitHeld(Within).Should().BeTrue("the older reload has read the mapping");
        await Sql("DELETE FROM AdGroupRoleMappings");   // the mapping is removed in Administration
        await Task.Run(directory.Invalidate);
        held.Release();
        await older;

        directory.RolesForGroups([@"CORP\SOC"]).Should().BeEmpty("a removed mapping isn't put back by a slower, older reload");
        directory.IsCurrent.Should().BeTrue();
    }

    [Fact]
    public async Task A_user_directory_reload_that_read_first_cant_store_last()
    {
        using var held = new HeldReadInterceptor("Users");
        await using var services = new ServiceCollection()
            .AddDbContext<AppDbContext>(o => o.UseSqlite(Conn).AddInterceptors(held)).BuildServiceProvider();
        await AddUserAsync(services, "S-1-5-21-1");
        var directory = new UserDirectory(services.GetRequiredService<IServiceScopeFactory>());

        held.Arm();
        var older = Task.Run(directory.Invalidate);
        held.WaitHeld(Within).Should().BeTrue("the older reload has read one user");
        await AddUserAsync(services, "S-1-5-21-2");
        await Task.Run(directory.Invalidate);
        held.Release();
        await older;

        directory.Resolve("S-1-5-21-2").Should().NotBeNull("the newer reload's read stands");
    }

    private static async Task AddUserAsync(ServiceProvider services, string sid)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Users.Add(new AppUser { Sid = sid, DisplayName = sid, UserPrincipalName = sid, RolesCsv = "Analyst" });
        await db.SaveChangesAsync();
    }

    private async Task Sql(string sql)
    {
        await using var connection = new SqliteConnection(Conn);
        await connection.OpenAsync();
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync();
    }

    // ---- BUG-628: the token-owner check ----

    private const string Managers = "S-1-5-21-7-1101";
    private volatile bool _ownerEnabled;

    private sealed class ByName : IRoleDirectory
    {
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) => new HashSet<Permission>();
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) =>
            adGroups.Any(g => g == @"CORP\SOC-Managers") ? new HashSet<string> { "Manager" } : new HashSet<string>();
        public IReadOnlySet<string> RolesMappedByName => new HashSet<string> { "Manager" };
        public bool IsRole(string name) => name == "Manager";
        public void Invalidate() { }
    }

    /// <summary>The directory naming groups: holds naming the managers group until released.</summary>
    private sealed class HeldLsa : IDisposable
    {
        public readonly ManualResetEventSlim Entered = new();
        public readonly ManualResetEventSlim Release = new();
        public IReadOnlyDictionary<string, string> Translate(IReadOnlyList<string> sids)
        {
            if (sids.Contains(Managers))
            {
                Entered.Set();
                Release.Wait(TimeSpan.FromSeconds(30));
            }
            return sids.ToDictionary(s => s, _ => @"CORP\SOC-Managers");
        }
        public void Dispose()
        {
            Release.Set();
            Entered.Dispose();
            Release.Dispose();
        }
    }

    [Fact]
    public async Task An_older_enabled_answer_cant_land_after_a_newer_disabled_one(/* BUG-628 */)
    {
        using var lsa = new HeldLsa();
        _ownerEnabled = true;
        var check = new AdTokenOwnerCheck(new ByName(), _clock,
            lookup: _ => _ownerEnabled ? new(true, [Managers]) : new(false, []),
            sids: new SidNames(lsa.Translate, TimeSpan.FromSeconds(30)));

        // The older lookup answers "enabled", then is slow naming the owner's groups.
        var older = check.CheckAsync(@"CORP\mgr");
        lsa.Entered.Wait(Within).Should().BeTrue("the older check is naming the groups");

        // Meanwhile the owner is disabled, and a newer check reads that.
        _ownerEnabled = false;
        (await check.CheckAsync(@"CORP\mgr"))!.Active.Should().BeFalse();

        lsa.Release.Set();
        var olderAnswer = await older;

        olderAnswer!.Active.Should().BeFalse("the newer lookup's answer stands, also for the older caller");
        var after = await check.CheckAsync(@"CORP\mgr");
        after!.Active.Should().BeFalse("a disabled owner's token doesn't get its roles back from a slower, older answer");
        after!.Roles.Should().BeEmpty();
    }

    // ---- BUG-642: a newer partial answer doesn't block an older whole one ----

    private const string Admins = "S-1-5-21-7-1201";
    private const string Analysts = "S-1-5-21-7-1202";
    private const string AnalystsMoved = "S-1-5-21-7-1203";   // the analysts group, as the older lookup read it
    private const string Unnamed = "S-1-5-21-7-1204";         // a group the directory fails to name

    private sealed class AdminsAndAnalysts : IRoleDirectory
    {
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) => new HashSet<Permission>();
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) => adGroups
            .Select(g => g switch { @"CORP\SOC-Admins" => "Admin", @"CORP\SOC-Analysts" => "Analyst", _ => null })
            .OfType<string>().ToHashSet();
        public IReadOnlySet<string> RolesMappedByName => new HashSet<string> { "Admin", "Analyst" };
        public bool IsRole(string name) => name is "Admin" or "Analyst";
        public void Invalidate() { }
    }

    /// <summary>Names the admins and analysts groups; holds naming <see cref="AnalystsMoved"/> until released, and fails
    /// on <see cref="Unnamed"/>.</summary>
    private sealed class NamingLsa : IDisposable
    {
        public readonly ManualResetEventSlim Entered = new();
        public readonly ManualResetEventSlim Release = new();
        public IReadOnlyDictionary<string, string> Translate(IReadOnlyList<string> sids)
        {
            if (sids.Contains(Unnamed)) throw new InvalidOperationException("RPC server unavailable");
            if (sids.Contains(AnalystsMoved))
            {
                Entered.Set();
                Release.Wait(TimeSpan.FromSeconds(30));
            }
            return sids.ToDictionary(s => s, s => s == Admins ? @"CORP\SOC-Admins" : @"CORP\SOC-Analysts");
        }
        public void Dispose()
        {
            Release.Set();
            Entered.Dispose();
            Release.Dispose();
        }
    }

    [Fact]
    public async Task An_older_whole_answer_lands_after_a_newer_partial_one(/* BUG-642 */)
    {
        using var lsa = new NamingLsa();
        IReadOnlyList<string> groups = [Admins, Analysts];
        var check = new AdTokenOwnerCheck(new AdminsAndAnalysts(), _clock,
            lookup: _ => new(true, Volatile.Read(ref groups)),
            sids: new SidNames(lsa.Translate, TimeSpan.FromSeconds(30)));
        (await check.CheckAsync(@"CORP\owner"))!.Roles.Should().BeEquivalentTo(["Admin", "Analyst"]);

        // The answer is stale, and the owner has been taken out of the admins group. The older lookup reads that, then
        // is slow naming the groups.
        _clock.UtcNow += AdTokenOwnerCheck.Fresh;
        Volatile.Write(ref groups, [AnalystsMoved]);
        var older = check.CheckAsync(@"CORP\owner");
        lsa.Entered.Wait(Within).Should().BeTrue("the older check is naming the groups");

        // A newer lookup's groups aren't all named: a partial answer, stored as such.
        Volatile.Write(ref groups, [Unnamed]);
        await check.CheckAsync(@"CORP\owner");

        lsa.Release.Set();
        (await older)!.Roles.Should().Equal(["Analyst"], "the older lookup's whole answer is the best one there is");
        var after = await check.CheckAsync(@"CORP\owner");
        after!.Active.Should().BeTrue();
        after.Roles.Should().Equal(["Analyst"], "the removed admins group takes Admin away at once, not after the retry wait");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var path in new[] { _dbPath, _emptyPath })
            if (File.Exists(path)) File.Delete(path);
    }
}
