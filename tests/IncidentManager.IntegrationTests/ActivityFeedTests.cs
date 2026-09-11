using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Activity;
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

public sealed class ActivityFeedTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 11, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public ActivityFeedTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.Manager]; // sees all cases
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
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private sealed class NoOpCaseNotifications : IncidentManager.Application.Abstractions.ICaseNotifications
    {
        public System.Threading.Tasks.Task OnAssignedAsync(IncidentManager.Domain.Entities.Case c, string assigneeUserId, string assigneeDisplayName, IncidentManager.Domain.Enums.CaseAssignmentRole role, string assignedByUserId, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public System.Threading.Tasks.Task OnActionItemsOverdueAsync(System.Collections.Generic.IReadOnlyList<IncidentManager.Application.Abstractions.OverdueActionItem> items, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public Task OnReclassifiedAsync(IncidentManager.Domain.Entities.Case c, Classification? from, Classification to, CancellationToken ct = default)
            => Task.CompletedTask;
    }

    /// <summary>Identity directory: resolves ids to themselves — enough for feed tests.</summary>
    private sealed class StubUserDirectory : IncidentManager.Application.Abstractions.IUserDirectory
    {
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<IncidentManager.Application.Abstractions.UserSummary> All() => Array.Empty<IncidentManager.Application.Abstractions.UserSummary>();
        public IncidentManager.Application.Abstractions.UserSummary? Resolve(string userId) => null;
        public string DisplayFor(string? userId) => userId ?? "—";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
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
    public async Task Feed_returns_recent_case_activity_newest_first_with_deep_link_ids()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = await svc.CreateAsync(Req("Alpha"));
        await svc.CreateAsync(Req("Beta"));
        await svc.AddNoteAsync(alpha.Id, "First analyst observation");

        var feed = new ActivityFeedService(NewFactory(), _user, new StubUserDirectory());
        var items = await feed.RecentAsync(20);

        items.Should().NotBeEmpty();
        // Most recent action was the note on Alpha.
        var top = items[0];
        top.CaseId.Should().Be(alpha.Id);
        top.CaseNumber.Should().Be(alpha.CaseNumber);
        top.Summary.Should().Contain("note");
        // Newest-first ordering by chain sequence.
        items.Select(i => i.Sequence).Should().BeInDescendingOrder();
    }

    [Fact]
    public async Task Feed_only_includes_cases_the_caller_can_see()
    {
        // Seed a restricted case as a privileged user...
        Guid restrictedId;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var restricted = await svc.CreateAsync(Req("Restricted"));
            restrictedId = restricted.Id;
            await svc.AddNoteAsync(restricted.Id, "Sensitive detail");
            var entity = await db.Cases.FirstAsync(c => c.Id == restrictedId);
            entity.IsRestricted = true;
            await db.SaveChangesAsync();
        }

        // ...then read the feed as an unassigned analyst (need-to-know applies).
        var analyst = new TestCurrentUser { UserId = "analyst-not-assigned" };
        analyst.RoleSet = [AppRole.Analyst];
        var factory2 = new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection).Options);

        var feed = new ActivityFeedService(factory2, analyst, new StubUserDirectory());
        var items = await feed.RecentAsync(20);

        items.Should().NotContain(i => i.CaseId == restrictedId);
    }

    public void Dispose() => _connection.Dispose();
}
