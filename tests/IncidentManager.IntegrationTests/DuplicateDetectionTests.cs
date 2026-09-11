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
/// E-23: at case creation, entered indicators are checked against the entities of visible OPEN cases so a
/// duplicate / same-campaign case surfaces before filing. Matching is value-based, refang-aware, and
/// need-to-know scoped; closed/archived cases are excluded.
/// </summary>
public sealed class DuplicateDetectionTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 26, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public DuplicateDetectionTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.Manager]; // sees all cases unless a test overrides
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

    private CaseService NewService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private sealed class NoOpCaseNotifications : ICaseNotifications
    {
        public System.Threading.Tasks.Task OnAssignedAsync(IncidentManager.Domain.Entities.Case c, string assigneeUserId, string assigneeDisplayName, IncidentManager.Domain.Enums.CaseAssignmentRole role, string assignedByUserId, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public System.Threading.Tasks.Task OnActionItemsOverdueAsync(System.Collections.Generic.IReadOnlyList<IncidentManager.Application.Abstractions.OverdueActionItem> items, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public System.Threading.Tasks.Task OnActionItemsDueSoonAsync(System.Collections.Generic.IReadOnlyList<IncidentManager.Application.Abstractions.DueSoonActionItem> items, int leadHours, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public Task OnReclassifiedAsync(IncidentManager.Domain.Entities.Case c, Classification? from, Classification to, CancellationToken ct = default)
            => Task.CompletedTask;
    }

    private static CreateCaseRequest Req(string name) => new()
    {
        DescriptiveName = name,
        Title = $"{name} case",
        Classification = Classification.Incident,
        Severity = Severity.Medium,
        Origin = CaseOrigin.InternalDetection
    };

    [Fact]
    public async Task Only_open_visible_cases_match_and_a_defanged_paste_matches_the_live_value()
    {
        Guid openId;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            openId = (await svc.CreateAsync(Req("Open"))).Id;
            await svc.AddEntityAsync(openId, EntityType.IpAddress, "203.0.113.5", null, EntityDisposition.Malicious, null, "seed");

            var closed = (await svc.CreateAsync(Req("Closed"))).Id;
            await svc.AddEntityAsync(closed, EntityType.IpAddress, "203.0.113.5", null, EntityDisposition.Malicious, null, "seed");
            var archived = (await svc.CreateAsync(Req("Archived"))).Id;
            await svc.AddEntityAsync(archived, EntityType.IpAddress, "203.0.113.5", null, EntityDisposition.Malicious, null, "seed");

            var cClosed = await db.Cases.FirstAsync(c => c.Id == closed);
            cClosed.ChangePhase(CasePhase.Closed, "resolved", _user.UserId, _clock.UtcNow);
            var cArchived = await db.Cases.FirstAsync(c => c.Id == archived);
            cArchived.IsArchived = true;
            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            // Defanged input must match the live stored "203.0.113.5"; the unrelated indicator matches nothing.
            var matches = await svc.FindOpenCaseMatchesForIocsAsync(new[] { "203.0.113[.]5", "not-present.example" });

            matches.Should().ContainSingle();
            matches[0].CaseId.Should().Be(openId);
            matches[0].Indicators.Should().ContainSingle().Which.Should().Be("203.0.113.5");
        }
    }

    [Fact]
    public async Task Restricted_cases_the_caller_cannot_see_are_excluded()
    {
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var r = IncidentManager.Domain.Entities.Case.Open(2026, 99, "Restricted", "Restricted",
                Classification.Breach, Severity.High, CaseOrigin.InternalDetection, "someone-else", _clock.UtcNow);
            r.IsRestricted = true;
            db.Cases.Add(r);
            await db.SaveChangesAsync();
            await svc.AddEntityAsync(r.Id, EntityType.Domain, "evil.example.com", null, EntityDisposition.Malicious, null, "seed");
        }

        // An analyst who is neither IC nor assigned on the restricted case can't see it.
        _user.UserId = "analyst-not-assigned";
        _user.RoleSet = [AppRole.Analyst];

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            (await svc.FindOpenCaseMatchesForIocsAsync(new[] { "evil.example.com" })).Should().BeEmpty();
        }
    }

    [Fact]
    public async Task Matches_group_by_case_and_order_by_shared_indicator_count()
    {
        Guid two, one;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            two = (await svc.CreateAsync(Req("Two"))).Id;
            await svc.AddEntityAsync(two, EntityType.IpAddress, "1.1.1.1", null, EntityDisposition.Malicious, null, "s");
            await svc.AddEntityAsync(two, EntityType.Domain, "bad.example.com", null, EntityDisposition.Malicious, null, "s");
            one = (await svc.CreateAsync(Req("One"))).Id;
            await svc.AddEntityAsync(one, EntityType.IpAddress, "1.1.1.1", null, EntityDisposition.Malicious, null, "s");
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var matches = await svc.FindOpenCaseMatchesForIocsAsync(new[] { "1.1.1.1", "bad.example.com" });

            matches.Should().HaveCount(2);
            matches[0].CaseId.Should().Be(two); // two shared indicators sorts first
            matches[0].Indicators.Should().BeEquivalentTo(new[] { "1.1.1.1", "bad.example.com" });
            matches[1].CaseId.Should().Be(one);
            matches[1].Indicators.Should().ContainSingle().Which.Should().Be("1.1.1.1");
        }
    }

    public void Dispose() => _connection.Dispose();
}
