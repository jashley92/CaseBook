using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
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
