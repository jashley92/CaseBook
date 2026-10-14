using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Work;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// E-39: the agenda board buckets open, dated after-action items by due band, filters by owner, and scopes
/// to what the caller may see; the feed query returns only a given user's own dated items. Read-only.
/// </summary>
public sealed class AgendaServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 10, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();   // analyst1, Analyst role (no ViewAllCases)

    public AgendaServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = NewContext();
        db.Database.EnsureCreated();
    }

    private AppDbContext NewContext() =>
        new(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options);

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options);

    private sealed class FakeDirectory : IUserDirectory
    {
        private readonly Dictionary<string, UserSummary> _u = new(StringComparer.OrdinalIgnoreCase)
        {
            ["analyst1"] = new("analyst1", "Analyst One", "analyst1@contoso.example", "analyst1@contoso.example", ""),
            ["bob"] = new("bob", "Bob Builder", "bob@contoso.example", "bob@contoso.example", ""),
        };
        public Task TouchAsync(string id, string n, string? u, string? e, string r, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<UserSummary> All() => _u.Values.ToList();
        public UserSummary? Resolve(string id) => _u.GetValueOrDefault(id);
        public string DisplayFor(string? id) => id is not null && _u.TryGetValue(id, out var s) ? s.DisplayName : (id ?? "—");
        public string? EmailFor(string id) => _u.GetValueOrDefault(id)?.Email;
        public void Invalidate() { }
    }

    private AgendaService NewService() => new(NewFactory(), _user, new FakeDirectory(), _clock);

    private void Seed()
    {
        using var db = NewContext();
        var now = _clock.UtcNow;

        var a = Case.Open(2026, 1, "Case A", "Visible case", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "ic1", now);   // not restricted → visible to all
        a.ActionItems.Add(new ActionItem { CaseId = a.Id, Title = "Overdue mine", Owner = "analyst1", DueAtUtc = now.AddDays(-1), Status = ActionItemStatus.Open });
        a.ActionItems.Add(new ActionItem { CaseId = a.Id, Title = "Today bob", Owner = "bob", DueAtUtc = now.AddHours(2), Status = ActionItemStatus.Open });
        a.ActionItems.Add(new ActionItem { CaseId = a.Id, Title = "Week mine", Owner = "analyst1", DueAtUtc = now.AddDays(3), Status = ActionItemStatus.Open });
        a.ActionItems.Add(new ActionItem { CaseId = a.Id, Title = "Later bob", Owner = "bob", DueAtUtc = now.AddDays(30), Status = ActionItemStatus.Open });
        a.ActionItems.Add(new ActionItem { CaseId = a.Id, Title = "Undated mine", Owner = "analyst1", DueAtUtc = null, Status = ActionItemStatus.Open });
        a.ActionItems.Add(new ActionItem { CaseId = a.Id, Title = "Done mine", Owner = "analyst1", DueAtUtc = now.AddDays(-1), Status = ActionItemStatus.Done });

        var b = Case.Open(2026, 2, "Case B", "Restricted case", Classification.Incident, Severity.Critical,
            CaseOrigin.InternalDetection, "ic2", now);
        b.IsRestricted = true;   // analyst1 is neither IC nor assignee → invisible to them
        b.ActionItems.Add(new ActionItem { CaseId = b.Id, Title = "Hidden mine", Owner = "analyst1", DueAtUtc = now.AddDays(-2), Status = ActionItemStatus.Open });

        db.Cases.AddRange(a, b);
        db.SaveChanges();
    }

    [Fact]
    public async Task Board_buckets_visible_items_by_due_band()
    {
        Seed();
        var board = await NewService().GetBoardAsync();

        board.TotalCount.Should().Be(5);   // Case B's item is not visible to the analyst
        board.Buckets.Select(x => x.Kind).Should().Equal(
            AgendaBucketKind.Overdue, AgendaBucketKind.Today, AgendaBucketKind.ThisWeek,
            AgendaBucketKind.Later, AgendaBucketKind.NoDueDate);
        board.Buckets.Single(x => x.Kind == AgendaBucketKind.Overdue).Items.Single().Title.Should().Be("Overdue mine");
        board.Buckets.Single(x => x.Kind == AgendaBucketKind.Today).Items.Single().Title.Should().Be("Today bob");
    }

    [Fact]
    public async Task A_closed_cases_tasks_are_off_the_board(/* BUG-211 */)
    {
        Seed();
        await using (var db = NewContext())
        {
            var c = Case.Open(2026, 3, "Case C", "Closed case", Classification.Incident, Severity.Low,
                CaseOrigin.InternalDetection, "ic1", _clock.UtcNow.AddDays(-5));
            c.ActionItems.Add(new ActionItem { CaseId = c.Id, Title = "Left over", Owner = "analyst1", DueAtUtc = _clock.UtcNow.AddDays(-1) });
            c.ChangePhase(CasePhase.Closed, "Done", "ic1", _clock.UtcNow.AddDays(-2));
            db.Cases.Add(c);
            await db.SaveChangesAsync();
        }

        (await NewService().GetBoardAsync()).Buckets.SelectMany(b => b.Items).Should().NotContain(i => i.Title == "Left over");
    }

    [Fact]
    public async Task Board_owner_options_count_visible_items()
    {
        Seed();
        var board = await NewService().GetBoardAsync();

        board.Owners.Should().Contain(o => o.OwnerUserId == "analyst1" && o.Count == 3);
        board.Owners.Should().Contain(o => o.OwnerUserId == "bob" && o.Count == 2);
    }

    [Fact]
    public async Task Board_filters_to_my_items()
    {
        Seed();
        var board = await NewService().GetBoardAsync(AgendaService.MineOwnerFilter);

        board.TotalCount.Should().Be(3);
        board.Buckets.SelectMany(b => b.Items).Should().OnlyContain(i => i.OwnedByMe);
    }

    [Fact]
    public async Task Board_filters_to_a_specific_owner()
    {
        Seed();
        var board = await NewService().GetBoardAsync("bob");

        board.TotalCount.Should().Be(2);
        board.Buckets.SelectMany(b => b.Items).Should().OnlyContain(i => i.OwnerUserId == "bob");
    }

    [Fact]
    public async Task Feed_returns_only_the_users_own_dated_items()
    {
        Seed();
        var mine = await NewService().GetFeedItemsAsync("analyst1");

        // Owned + dated on the visible case: overdue + week. Undated dropped; restricted case excluded.
        mine.Select(i => i.Title).Should().BeEquivalentTo("Overdue mine", "Week mine");
        mine.Should().OnlyContain(i => i.DueAtUtc != null);
    }

    [Fact]
    public async Task Feed_excludes_a_restricted_case_the_user_is_not_on()
    {
        Seed();
        var mine = await NewService().GetFeedItemsAsync("analyst1");

        mine.Should().NotContain(i => i.Title == "Hidden mine");
    }

    private sealed class Roles : IRoleDirectory
    {
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) =>
            roleNames.Contains("Cleared") ? new HashSet<Permission> { Permission.ViewCases, Permission.ViewRestricted }
            : roleNames.Contains("Analyst") ? new HashSet<Permission> { Permission.ViewCases } : new HashSet<Permission>();
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) => new HashSet<string>();
        public void Invalidate() { }
    }

    private sealed class Ad(string role) : IncidentManager.Application.ApiTokens.ITokenOwnerCheck
    {
        public Task<IncidentManager.Application.ApiTokens.OwnerAccess?> CheckAsync(string ownerUserId, CancellationToken ct = default) =>
            Task.FromResult<IncidentManager.Application.ApiTokens.OwnerAccess?>(new(true, new HashSet<string> { role }));
    }

    [Theory]
    [InlineData("Cleared", true)]
    [InlineData("Analyst", false)]
    public async Task Feed_includes_a_restricted_task_the_user_owns_only_when_cleared(string role, bool listed /* BUG-401 */)
    {
        Seed();
        var service = new AgendaService(NewFactory(), _user, new FakeDirectory(), _clock, new Roles(), new Ad(role));

        var mine = await service.GetFeedItemsAsync("analyst1");

        mine.Any(i => i.Title == "Hidden mine").Should().Be(listed,
            "the task reminder goes to a cleared owner, and the digest replaces it, so the digest must list it");
        mine.Should().Contain(i => i.Title == "Overdue mine");
    }

    public void Dispose() => _connection.Dispose();
}
