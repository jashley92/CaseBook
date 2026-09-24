using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>PROD-07: per-jurisdiction notification-deadline rules + the per-case deadline evaluation.</summary>
public sealed class NotificationDeadlineServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 16, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] }; // admin/config writes assert Administer (F-23)
    private readonly StubSettings _settings = new();

    public NotificationDeadlineServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = NewContext();
    }

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private NotificationRuleService NewRules() => new(NewFactory(), _user, _clock);
    private NotificationDeadlineService NewService() =>
        new(NewFactory(), _settings, NewRules(), _clock);

    /// <summary>A Breach case whose SSN data element triggers the "NY" jurisdiction, determined material.</summary>
    private async Task<Guid> SeedMaterialBreachAsync(MaterialityStatus materiality = MaterialityStatus.Material)
    {
        await using var db = NewContext();
        db.DataElements.Add(new DataElement
        {
            Key = "SSN", Label = "Social Security number", NotificationJurisdictions = "NY",
            IsActive = true, IsSystem = false, CreatedBy = "system", CreatedAtUtc = _clock.UtcNow
        });
        var c = Case.Open(2026, 1, "Breach", "Breach case", Classification.Breach, Severity.High,
            CaseOrigin.InternalDetection, "alice", _clock.UtcNow);
        c.SetImpactAssessment(500, new[] { "SSN" }, "NY", "alice", _clock.UtcNow);
        if (materiality == MaterialityStatus.Material)
            c.RecordMateriality(MaterialityStatus.Material, "Disclosure Committee", _clock.UtcNow.AddHours(-1),
                "Reasonable likelihood of harm.", "alice", _clock.UtcNow);
        else if (materiality != MaterialityStatus.Undetermined)
            c.RecordMateriality(materiality, "Committee", _clock.UtcNow.AddHours(-1), "n/a", "alice", _clock.UtcNow);
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return c.Id;
    }

    [Fact]
    public async Task When_the_feature_is_off_nothing_is_evaluated()
    {
        var id = await SeedMaterialBreachAsync();
        _settings.Current = NotificationDeadlineSettings.Off;
        (await NewService().EvaluateAsync(id)).Enabled.Should().BeFalse();
    }

    [Fact]
    public async Task A_material_breach_gets_a_per_jurisdiction_countdown_that_stops_when_reported()
    {
        var id = await SeedMaterialBreachAsync();
        await NewRules().SaveAsync(null, "NY", "New York (NYDFS Part 500)", 72);
        _settings.Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 72, 80);

        var result = await NewService().EvaluateAsync(id);
        result.HasClock.Should().BeTrue();
        var ny = result.Statuses.Should().ContainSingle().Subject;
        ny.JurisdictionCode.Should().Be("NY");
        ny.WindowHours.Should().Be(72);
        ny.State.Should().Be(SlaState.OnTrack); // decided 1h ago, well inside 72h

        // Recording the reported milestone stops the clock (Met, since we are inside the window).
        await using (var db = NewContext())
        {
            var c = await db.Cases.FirstAsync(x => x.Id == id);
            c.MarkReported(_clock.UtcNow, "alice", _clock.UtcNow);
            await db.SaveChangesAsync();
        }

        var after = await NewService().EvaluateAsync(id);
        after.ReportedAtUtc.Should().NotBeNull();
        after.Statuses.Single().State.Should().Be(SlaState.Met);
    }

    [Fact]
    public async Task A_jurisdiction_without_a_rule_uses_the_default_window()
    {
        var id = await SeedMaterialBreachAsync();
        // No NY rule saved → the default window (48h) applies.
        _settings.Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 48, 80);

        var ny = (await NewService().EvaluateAsync(id)).Statuses.Should().ContainSingle().Subject;
        ny.WindowHours.Should().Be(48);
    }

    [Fact]
    public async Task An_undetermined_case_is_awaiting_the_trigger_under_determination_basis()
    {
        var id = await SeedMaterialBreachAsync(MaterialityStatus.Undetermined);
        _settings.Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 72, 80);

        var result = await NewService().EvaluateAsync(id);
        result.AwaitingTrigger.Should().BeTrue();
        result.Statuses.Should().BeEmpty();
    }

    [Fact]
    public async Task Rules_are_audited_and_the_code_is_unique()
    {
        await NewRules().SaveAsync(null, "ny", "New York", 72);   // lower-case is normalised to NY
        var act = async () => await NewRules().SaveAsync(null, "NY", "Dup", 24);
        await act.Should().ThrowAsync<InvalidOperationException>();

        await using var db = NewContext();
        (await db.NotificationRules.CountAsync(r => r.Code == "NY")).Should().Be(1);
        (await db.AuditLog.CountAsync(a => a.EntityType == "NotificationRule")).Should().BeGreaterThan(0);
        _hasher.VerifyChain(await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
    }

    private sealed class StubSettings : INotificationDeadlineSettingsProvider
    {
        public NotificationDeadlineSettings Current { get; set; } = NotificationDeadlineSettings.Off;
    }

    public void Dispose() => _connection.Dispose();
}
