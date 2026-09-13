using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Views;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>PROD-09: named / shared case-queue views — ownership scoping, sharing, upsert, delete.</summary>
public sealed class SavedViewTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();
    private readonly StubUserDirectory _dir = new();

    public SavedViewTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
    }

    private DbContextOptions<AppDbContext> Options() =>
        new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options;

    private SavedViewService NewService() => new(new TestDbContextFactory(Options()), _user, _dir, _clock);

    /// <summary>Identity user directory — resolves an id to a readable name for the "shared by" label.</summary>
    private sealed class StubUserDirectory : IUserDirectory
    {
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<UserSummary> All() => Array.Empty<UserSummary>();
        public UserSummary? Resolve(string userId) => null;
        public string DisplayFor(string? userId) => userId ?? "—";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
    }

    [Fact]
    public async Task A_personal_view_is_visible_only_to_its_owner()
    {
        _user.UserId = "alice";
        await NewService().SaveAsync("My triage queue", "scope=mine&sla=true", isShared: false);

        var mine = await NewService().ListAsync();
        mine.Should().ContainSingle(v => v.Name == "My triage queue" && v.IsMine && !v.IsShared);

        _user.UserId = "bob";
        (await NewService().ListAsync()).Should().BeEmpty();   // not shared → invisible to Bob
    }

    [Fact]
    public async Task A_shared_view_is_visible_to_the_team_and_marked_not_mine()
    {
        _user.UserId = "alice";
        await NewService().SaveAsync("Breaches on hold", "classification=Breach&hold=true", isShared: true);

        _user.UserId = "bob";
        var seen = await NewService().ListAsync();
        var v = seen.Should().ContainSingle().Subject;
        v.Name.Should().Be("Breaches on hold");
        v.IsShared.Should().BeTrue();
        v.IsMine.Should().BeFalse();
        v.OwnerName.Should().Be("alice");     // resolved via the directory
        v.Query.Should().Be("classification=Breach&hold=true");
    }

    [Fact]
    public async Task Saving_the_same_name_updates_in_place_rather_than_duplicating()
    {
        _user.UserId = "alice";
        var svc = NewService();
        var id1 = await svc.SaveAsync("Queue", "sla=true", isShared: false);
        var id2 = await NewService().SaveAsync("Queue", "overdue=true&closed=true", isShared: true);

        id2.Should().Be(id1);                 // same view, updated
        var views = await NewService().ListAsync();
        var v = views.Should().ContainSingle().Subject;
        v.Query.Should().Be("overdue=true&closed=true");
        v.IsShared.Should().BeTrue();
    }

    [Fact]
    public async Task A_leading_question_mark_is_stripped_when_saving()
    {
        _user.UserId = "alice";
        await NewService().SaveAsync("Q", "?scope=mine&sla=true", isShared: false);
        (await NewService().ListAsync()).Single().Query.Should().Be("scope=mine&sla=true");
    }

    [Fact]
    public async Task A_blank_name_is_rejected()
    {
        _user.UserId = "alice";
        var act = async () => await NewService().SaveAsync("   ", "sla=true", isShared: false);
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task An_owner_can_delete_their_view_but_not_someone_elses()
    {
        _user.UserId = "alice";
        var id = await NewService().SaveAsync("Shared", "sla=true", isShared: true);

        // Bob can see it (shared) but cannot delete it.
        _user.UserId = "bob";
        var del = async () => await NewService().DeleteAsync(id);
        await del.Should().ThrowAsync<InvalidOperationException>();

        // Alice can.
        _user.UserId = "alice";
        await NewService().DeleteAsync(id);
        (await NewService().ListAsync()).Should().BeEmpty();
    }

    public void Dispose() => _connection.Dispose();
}
