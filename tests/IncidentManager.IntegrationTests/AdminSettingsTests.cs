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

    private sealed class FailedReload : IncidentManager.Application.Abstractions.ISettingsReloader
    {
        public void Reload() { }
        public string? LastError => "timeout";
    }

    [Fact]
    public async Task A_save_the_reload_couldnt_apply_says_so(/* REV-60 */)
    {
        await using var db = NewContext();
        var svc = new AdminSettingsService(NewFactory(), _user, _clock, new FailedReload());

        var set = async () => await svc.SetAsync("Email:Enabled", "true");

        await set.Should().ThrowAsync<InvalidOperationException>().WithMessage("Saved, but not in effect yet*timeout*");
        (await db.AppSettings.AsNoTracking().SingleAsync(x => x.Key == "Email:Enabled")).Value.Should().Be("true", "it was saved");
    }

    [Fact]
    public async Task A_save_or_reset_the_reload_couldnt_apply_is_told_apart_from_one_that_didnt_happen(/* BUG-526 */)
    {
        await using var db = NewContext();
        var svc = new AdminSettingsService(NewFactory(), _user, _clock, new FailedReload());

        // The page treats this one as saved: it moves its baseline on and carries on with the rest of the section.
        (await svc.Invoking(s => s.SetAsync("Reporting:SectionLayout", "[]", null)).Should().ThrowAsync<SettingsNotInEffectException>())
            .Which.ReloadError.Should().Be("timeout");
        // So the retry from the reloaded page (the stored value as its baseline) isn't refused as a stale edit.
        var stored = (await svc.GetEffectiveAsync()).Single(e => e.Definition.Key == "Reporting:SectionLayout");
        stored.IsOverridden.Should().BeTrue();
        await svc.Invoking(s => s.SetAsync("Reporting:SectionLayout", "[]", stored.Value))
            .Should().ThrowAsync<SettingsNotInEffectException>("saved again, still not in effect, but not refused as stale");

        await svc.Invoking(s => s.ResetAsync("Reporting:SectionLayout")).Should().ThrowAsync<SettingsNotInEffectException>();
        (await db.AppSettings.AsNoTracking().AnyAsync(x => x.Key == "Reporting:SectionLayout")).Should().BeFalse("it was reset");
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

    private AdminSettingsService RacingService(RaceCommandInterceptor race) =>
        new(new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()), race)
            .Options), _user, _clock, new NoOpReloader());

    [Fact]
    public async Task A_reset_another_reset_beat_to_it_is_not_an_error(/* BUG-437 */)
    {
        await using var db = NewContext();
        const string key = "ExternalLinks:DetectionCaseUrlTemplate";
        await NewService(db).SetAsync(key, "https://siem/{0}");

        // A double click: the first reset deletes the row between the second's read and its delete.
        var race = new RaceCommandInterceptor("DELETE FROM \"AppSettings\"", "DELETE FROM \"AppSettings\" WHERE \"Key\" = $k", ("$k", key));
        await RacingService(race).ResetAsync(key);

        race.Ran.Should().BeTrue();
        (await db.AppSettings.AsNoTracking().AnyAsync(s => s.Key == key)).Should().BeFalse();
    }

    [Fact]
    public async Task Two_first_overrides_at_once_say_so_instead_of_an_error_page(/* BUG-459 */)
    {
        await using var db = NewContext();
        const string key = "ExternalLinks:DetectionCaseUrlTemplate";
        // Another administrator's first override of the key lands between this save's read and its insert.
        var race = new RaceCommandInterceptor("INSERT INTO \"AppSettings\"",
            "INSERT INTO \"AppSettings\" (\"Id\", \"Key\", \"Value\", \"UpdatedAtUtc\", \"UpdatedBy\") VALUES ($id, $k, 'https://other/{0}', 0, 'bob')",
            ("$id", Guid.NewGuid().ToString().ToUpperInvariant()), ("$k", key));

        var save = async () => await RacingService(race).SetAsync(key, "https://siem/{0}");

        await save.Should().ThrowAsync<InvalidOperationException>().WithMessage("Another administrator saved*at the same moment*");
        race.Ran.Should().BeTrue();
        (await db.AppSettings.AsNoTracking().SingleAsync(s => s.Key == key)).Value.Should().Be("https://other/{0}");
    }

    [Fact]
    public async Task A_save_that_loses_to_a_reset_says_the_setting_changed(/* BUG-459 */)
    {
        await using var db = NewContext();
        const string key = "ExternalLinks:DetectionCaseUrlTemplate";
        await NewService(db).SetAsync(key, "https://siem/{0}");
        // Another administrator resets it between this save's read and its update.
        var race = new RaceCommandInterceptor("UPDATE \"AppSettings\"", "DELETE FROM \"AppSettings\" WHERE \"Key\" = $k", ("$k", key));

        var save = async () => await RacingService(race).SetAsync(key, "https://siem2/{0}");

        (await save.Should().ThrowAsync<InvalidOperationException>().WithMessage("Someone changed*since you opened it*"))
            .Which.Should().NotBeOfType<IncidentManager.Application.Cases.ConcurrentEditException>("its message is about cases");
        race.Ran.Should().BeTrue();
    }

    [Fact]
    public async Task A_whole_value_saved_from_a_stale_page_is_refused(/* BUG-438 */)
    {
        await using var db = NewContext();
        var svc = NewService(db);
        const string key = "Reporting:SectionLayout";

        // Two admins open the page with nothing stored; one saves a layout.
        var first = "ExecutiveSummary:1,Timeline:0";
        var otherSaves = async () => await svc.SetAsync(key, first, expectedStored: null);
        await otherSaves.Should().NotThrowAsync();
        var stored = (await svc.GetEffectiveAsync()).Single(e => e.Definition.Key == key).Value;

        // The other page still thinks nothing is stored, so its save would undo that.
        var stale = async () => await svc.SetAsync(key, "Timeline:1", expectedStored: null);
        await stale.Should().ThrowAsync<InvalidOperationException>().WithMessage("Someone changed*since you opened it*");
        (await svc.GetEffectiveAsync()).Single(e => e.Definition.Key == key).Value.Should().Be(stored);

        // From the stored value it goes through.
        await svc.SetAsync(key, "Timeline:1", expectedStored: stored);
        (await svc.GetEffectiveAsync()).Single(e => e.Definition.Key == key).Value.Should().NotBe(stored);
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
