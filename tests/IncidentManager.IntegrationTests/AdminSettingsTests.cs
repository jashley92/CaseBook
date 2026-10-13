using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

public sealed class AdminSettingsTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 11, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public AdminSettingsTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.UserId = "admin1";
        _user.RoleSet = [AppRole.SysAdmin];
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

    private AdminSettingsService NewService(AppDbContext db) => new(NewFactory(), _user, _clock, new NoOpReloader());

    private sealed class NoOpReloader : IncidentManager.Application.Abstractions.ISettingsReloader
    {
        public void Reload() { }
    }

    [Fact]
    public async Task Set_persists_normalized_value_and_reports_it_as_overridden()
    {
        await using (var db = NewContext())
        {
            await NewService(db).SetAsync("Email:Enabled", " TRUE ");
        }

        await using (var db = NewContext())
        {
            var effective = await NewService(db).GetEffectiveAsync();
            var enabled = effective.Single(e => e.Definition.Key == "Email:Enabled");
            enabled.Value.Should().Be("true");
            enabled.IsOverridden.Should().BeTrue();

            // Untouched settings still report their catalog default.
            var from = effective.Single(e => e.Definition.Key == "Email:From");
            from.IsOverridden.Should().BeFalse();
            from.Value.Should().Be("incident-manager@localhost");
        }
    }

    [Fact]
    public async Task Set_is_audited_and_hash_chained()
    {
        await using var db = NewContext();
        await NewService(db).SetAsync("Retention:CaseYears", "5");

        // The change produced a hash-chained audit entry naming the AppSetting, and the chain verifies.
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        chain.Should().Contain(a => a.EntityType == nameof(IncidentManager.Domain.Entities.AppSetting));
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();

        // The stored row carries a row hash.
        var row = await db.AppSettings.AsNoTracking().SingleAsync(s => s.Key == "Retention:CaseYears");
        row.RowHash.Should().NotBeNullOrEmpty();
        row.UpdatedBy.Should().Be("admin1");
    }

    // Changing the reporting time zone regroups past months and quarters, so the change must be on the record.
    [Fact]
    public async Task Changing_the_reporting_time_zone_is_audited()
    {
        await using var db = NewContext();
        await NewService(db).SetAsync("Organization:TimeZone", "america/chicago");

        var row = await db.AppSettings.AsNoTracking().SingleAsync(s => s.Key == "Organization:TimeZone");
        row.Value.Should().Be("America/Chicago");
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        chain.Should().Contain(a => a.EntityType == nameof(IncidentManager.Domain.Entities.AppSetting) && a.EntityId == row.Id.ToString());
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task The_page_shows_what_the_servers_settings_file_puts_in_force(/* BUG-245 */)
    {
        // As the production template does: seals every 24 h (the catalog default is 6), and a Legal list.
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Integrity:AutoSeal:IntervalHours"] = "24",
            ["Email:LegalDistribution:0"] = "legal@contoso.com",
            ["Email:LegalDistribution:1"] = "privacy@contoso.com",
        }).Build();
        await using var db = NewContext();
        var svc = new AdminSettingsService(NewFactory(), _user, _clock, new NoOpReloader(),
            server: new IncidentManager.Infrastructure.Configuration.ServerSettingValues(config));

        var effective = await svc.GetEffectiveAsync();
        var seal = effective.Single(e => e.Definition.Key == "Integrity:AutoSeal:IntervalHours");
        seal.Value.Should().Be("24");
        seal.IsOverridden.Should().BeFalse();
        seal.ServerValueFromFile.Should().BeTrue();
        effective.Single(e => e.Definition.Key == "Email:LegalDistribution").Value.Should().Be("legal@contoso.com\nprivacy@contoso.com");
        effective.Single(e => e.Definition.Key == "Email:From").ServerValueFromFile.Should().BeFalse();

        await svc.SetAsync("Integrity:AutoSeal:IntervalHours", "12");
        var changed = (await svc.GetEffectiveAsync()).Single(e => e.Definition.Key == "Integrity:AutoSeal:IntervalHours");
        (changed.Value, changed.ServerValue).Should().Be(("12", "24"), "Reset goes back to the file's 24, not the default 6");
    }

    [Fact]
    public async Task Reset_removes_the_override_so_the_default_returns()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        await svc.SetAsync("ExternalLinks:DetectionCaseUrlTemplate", "https://siem/{0}");
        await svc.ResetAsync("ExternalLinks:DetectionCaseUrlTemplate");

        var effective = await svc.GetEffectiveAsync();
        effective.Single(e => e.Definition.Key == "ExternalLinks:DetectionCaseUrlTemplate")
            .IsOverridden.Should().BeFalse();
        (await db.AppSettings.AsNoTracking().AnyAsync()).Should().BeFalse();
    }

    [Fact]
    public async Task Set_rejects_a_non_whitelisted_key()
    {
        await using var db = NewContext();
        var act = () => NewService(db).SetAsync("ConnectionStrings:Default", "hacked");
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Set_rejects_an_invalid_typed_value()
    {
        await using var db = NewContext();
        var act = () => NewService(db).SetAsync("Retention:CaseYears", "-3");
        await act.Should().ThrowAsync<ArgumentException>();
    }

    public void Dispose() => _connection.Dispose();
}
