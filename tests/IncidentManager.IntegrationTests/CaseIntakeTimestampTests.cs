using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// FR-03: the detection time is captured at intake and anchors the response-SLA clock + dwell. A provided
/// instant is honoured (not silently replaced with filing time); omitting it defaults to now; and it is
/// validated exactly like the domain's UpdateDetails (no future detection; activity not after detection).
/// </summary>
public sealed class CaseIntakeTimestampTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public CaseIntakeTimestampTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
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

    private CaseService NewService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());


    private static CreateCaseRequest Req(string name, Action<CreateCaseRequest>? tweak = null)
    {
        var r = new CreateCaseRequest
        {
            DescriptiveName = name,
            Title = $"{name} case",
            Classification = Classification.Incident,
            Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        };
        tweak?.Invoke(r);
        return r;
    }

    [Fact]
    public async Task A_supplied_detection_time_is_persisted_not_replaced_with_filing_time()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var detected = new DateTimeOffset(2026, 8, 1, 12, 0, 0, TimeSpan.Zero); // a week before filing

        var created = await svc.CreateAsync(Req("Backdated", r => r.DetectedAtUtc = detected));

        var reloaded = await db.Cases.AsNoTracking().FirstAsync(c => c.Id == created.Id);
        reloaded.DetectedAtUtc.Should().Be(detected);
        reloaded.DetectedAtUtc.Should().NotBe(_clock.UtcNow); // not silently anchored to now
    }

    [Fact]
    public async Task An_omitted_detection_time_defaults_to_filing_time()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        var created = await svc.CreateAsync(Req("Now"));

        var reloaded = await db.Cases.AsNoTracking().FirstAsync(c => c.Id == created.Id);
        reloaded.DetectedAtUtc.Should().Be(_clock.UtcNow);
    }

    [Fact]
    public async Task A_future_detection_time_is_rejected()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        var act = async () => await svc.CreateAsync(Req("Future", r => r.DetectedAtUtc = _clock.UtcNow.AddDays(1)));

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*future*");
    }

    [Fact]
    public async Task Activity_after_detection_is_rejected()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        var act = async () => await svc.CreateAsync(Req("Ordering", r =>
        {
            r.DetectedAtUtc = new DateTimeOffset(2026, 8, 1, 0, 0, 0, TimeSpan.Zero);
            r.OccurredAtUtc = new DateTimeOffset(2026, 8, 2, 0, 0, 0, TimeSpan.Zero); // after detection
        }));

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*detected*");
    }

    [Fact]
    public async Task A_valid_initial_activity_time_is_persisted_for_dwell()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var detected = new DateTimeOffset(2026, 8, 5, 0, 0, 0, TimeSpan.Zero);
        var occurred = new DateTimeOffset(2026, 8, 1, 0, 0, 0, TimeSpan.Zero); // 4 days of dwell before detection

        var created = await svc.CreateAsync(Req("Dwell", r => { r.DetectedAtUtc = detected; r.OccurredAtUtc = occurred; }));

        var reloaded = await db.Cases.AsNoTracking().FirstAsync(c => c.Id == created.Id);
        reloaded.OccurredAtUtc.Should().Be(occurred);
        (reloaded.DetectedAtUtc!.Value - reloaded.OccurredAtUtc!.Value).Should().Be(TimeSpan.FromDays(4));
    }

    public void Dispose() => _connection.Dispose();
}
