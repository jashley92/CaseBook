using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Configuration;
using IncidentManager.Infrastructure.Notifications;
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
/// Proves the A-08 loop: an administered override in the AppSettings table wins over file config,
/// list-valued settings rebuild into arrays, and a Reload() reflects a later change.
/// </summary>
public sealed class DbSettingsConfigurationTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"im-cfg-{Guid.NewGuid():N}.db");
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 11, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };

    private string Conn => $"Data Source={_dbPath}";

    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(Conn)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(Conn)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private AdminSettingsService NewService(AppDbContext db) => new(NewFactory(), _user, _clock, new NoOpReloader());

    private sealed class NoOpReloader : IncidentManager.Application.Abstractions.ISettingsReloader
    {
        public void Reload() { }
    }

    private IConfigurationRoot BuildConfig() =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Email:From"] = "file@localhost" })
            .Add(new DbSettingsConfigurationSource("Sqlite", Conn))
            .Build();

    [Fact]
    public async Task Db_override_wins_over_file_and_list_settings_rebuild_into_arrays()
    {
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            await svc.SetAsync("Email:From", "soc@insurer.example");
            await svc.SetAsync("Email:LegalDistribution", "a@insurer.example\nb@insurer.example");
        }

        var config = BuildConfig();

        config["Email:From"].Should().Be("soc@insurer.example"); // DB beats the file value

        var options = config.GetSection("Email").Get<EmailOptions>()!;
        options.From.Should().Be("soc@insurer.example");
        options.LegalDistribution.Should().BeEquivalentTo("a@insurer.example", "b@insurer.example");
    }

    [Fact]
    public async Task Reload_reflects_a_later_change()
    {
        await using (var db = NewContext())
            await NewService(db).SetAsync("ExternalLinks:DetectionCaseUrlTemplate", "https://siem/{0}");

        var config = BuildConfig();
        config["ExternalLinks:DetectionCaseUrlTemplate"].Should().Be("https://siem/{0}");

        await using (var db = NewContext())
            await NewService(db).SetAsync("ExternalLinks:DetectionCaseUrlTemplate", "https://siem/v2/{0}");

        config.Reload();
        config["ExternalLinks:DetectionCaseUrlTemplate"].Should().Be("https://siem/v2/{0}");
    }

    [Fact]
    public async Task Non_whitelisted_row_is_ignored_on_load_and_flagged()
    {
        // S-02: a legitimate, whitelisted override — must still apply.
        await using (var db = NewContext())
            await NewService(db).SetAsync("Email:From", "soc@insurer.example");

        // A row SetAsync would REJECT, inserted out-of-band straight into the table (simulating DB
        // tamper / a restored backup) and targeting a security-critical key the app must never let the
        // DB override.
        await using (var bare = new AppDbContext(
            new DbContextOptionsBuilder<AppDbContext>().UseSqlite(Conn).Options))
        {
            bare.Database.EnsureCreated();
            bare.AppSettings.Add(new IncidentManager.Domain.Entities.AppSetting
            {
                Key = "ConnectionStrings:Default",
                Value = "Data Source=attacker-controlled.db",
                UpdatedAtUtc = _clock.UtcNow,
                UpdatedBy = "attacker"
            });
            await bare.SaveChangesAsync();
        }

        var config = BuildConfig();

        // The rogue key must NOT reach configuration (whitelist enforced on the read path)...
        config["ConnectionStrings:Default"].Should().BeNull();
        // ...the whitelisted override still applies (no regression)...
        config["Email:From"].Should().Be("soc@insurer.example");
        // ...and the ignored key is surfaced so the host can raise a tamper signal.
        DbSettingsConfigurationProvider.RejectedKeys.Should().Contain("ConnectionStrings:Default");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { File.Delete(_dbPath); } catch { /* best-effort temp cleanup */ }
    }
}
