using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Integrity;
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
/// After-action task management from user testing: append-only task commentary (audited + hash-chained),
/// reopening a completed task, and reassigning a task's owner.
/// </summary>
public sealed class ActionItemTasksTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();
    private readonly StubUserDirectory _dir = new();

    public ActionItemTasksTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin]; // sees all cases + may edit
        using var db = NewContext();
    }

    private DbContextOptions<AppDbContext> Options() =>
        new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() => new TestDbContextFactory(Options());

    private CaseService NewCaseService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private ActionItemCommentService NewCommentService() => new(NewFactory(), _user, _clock, _dir);

    private async Task<(Guid caseId, Guid taskId)> SeededCaseWithTaskAsync()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
        await NewCaseService(db).AddActionItemAsync(caseId, "Rotate exposed credentials", owner: null, dueAtUtc: null);
        var taskId = (await db.ActionItems.FirstAsync(a => a.CaseId == caseId && a.Title == "Rotate exposed credentials")).Id;
        return (caseId, taskId);
    }

    [Fact]
    public async Task Reopening_a_done_task_clears_the_completion_timestamp()
    {
        var (caseId, taskId) = await SeededCaseWithTaskAsync();
        await using var db = NewContext();
        var svc = NewCaseService(db);

        await svc.SetActionItemStatusAsync(caseId, taskId, ActionItemStatus.Done);
        (await db.ActionItems.AsNoTracking().FirstAsync(a => a.Id == taskId)).CompletedAtUtc.Should().NotBeNull();

        await svc.SetActionItemStatusAsync(caseId, taskId, ActionItemStatus.Open);
        var reopened = await db.ActionItems.AsNoTracking().FirstAsync(a => a.Id == taskId);
        reopened.Status.Should().Be(ActionItemStatus.Open);
        reopened.CompletedAtUtc.Should().BeNull();
    }

    [Fact]
    public async Task Editing_a_task_updates_all_fields_in_one_audited_change()
    {
        var (caseId, taskId) = await SeededCaseWithTaskAsync();
        await using var db = NewContext();
        var svc = NewCaseService(db);

        var due = new DateTimeOffset(2026, 9, 1, 17, 0, 0, TimeSpan.Zero);
        await svc.UpdateActionItemAsync(caseId, taskId, "Rotate exposed credentials (all)", "analyst1",
            due, ActionItemStatus.InProgress, "Coordinated with IAM.");

        var item = await db.ActionItems.AsNoTracking().FirstAsync(a => a.Id == taskId);
        item.Title.Should().Be("Rotate exposed credentials (all)");
        item.Owner.Should().Be("analyst1");
        item.DueAtUtc.Should().Be(due);
        item.Status.Should().Be(ActionItemStatus.InProgress);
        item.Description.Should().Be("Coordinated with IAM.");
        item.CompletedAtUtc.Should().BeNull(); // not Done
    }

    [Fact]
    public async Task An_audited_task_change_names_the_task_and_reads_the_status_in_words()
    {
        var (caseId, taskId) = await SeededCaseWithTaskAsync();
        await using (var db = NewContext())
            await NewCaseService(db).SetActionItemStatusAsync(caseId, taskId, ActionItemStatus.Done);

        await using var read = NewContext();
        var entry = await read.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == "ActionItem" && a.Action == AuditAction.Update)
            .OrderByDescending(a => a.Sequence)
            .FirstAsync();

        // Identity: the trail says WHICH task, captured at write time.
        entry.EntityLabel.Should().Be("Rotate exposed credentials");
        // Value: the status enum reads as words, not a raw number.
        AuditChangeDetail.Changes(entry).Should()
            .Contain(x => x.Label == "Status" && x.Before == "Open" && x.After == "Done");
        // The chain still verifies (the new label extends the canonical only where present).
        var chain = await read.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task A_task_can_be_reassigned_and_unassigned()
    {
        var (caseId, taskId) = await SeededCaseWithTaskAsync();
        await using var db = NewContext();
        var svc = NewCaseService(db);

        await svc.SetActionItemOwnerAsync(caseId, taskId, "bob");
        (await db.ActionItems.AsNoTracking().FirstAsync(a => a.Id == taskId)).Owner.Should().Be("bob");

        await svc.SetActionItemOwnerAsync(caseId, taskId, "   ");
        (await db.ActionItems.AsNoTracking().FirstAsync(a => a.Id == taskId)).Owner.Should().BeNull();
    }

    [Fact]
    public async Task Task_comments_persist_in_order_with_their_authors()
    {
        var (caseId, taskId) = await SeededCaseWithTaskAsync();

        _user.UserId = "alice";
        await NewCommentService().AddAsync(caseId, taskId, "Started the rotation.");
        _user.UserId = "bob";
        await NewCommentService().AddAsync(caseId, taskId, "Blocked on the vault owner.");

        var comments = await NewCommentService().ListForCaseAsync(caseId);
        comments.Should().HaveCount(2);
        comments[0].Body.Should().Be("Started the rotation.");
        comments[0].AuthorUserId.Should().Be("alice");
        comments[1].AuthorUserId.Should().Be("bob");
        comments.Should().OnlyContain(c => c.ActionItemId == taskId);
    }

    [Fact]
    public async Task An_empty_task_comment_is_rejected()
    {
        var (caseId, taskId) = await SeededCaseWithTaskAsync();
        var act = async () => await NewCommentService().AddAsync(caseId, taskId, "   ");
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task A_comment_on_an_unknown_task_is_rejected()
    {
        var (caseId, _) = await SeededCaseWithTaskAsync();
        var act = async () => await NewCommentService().AddAsync(caseId, Guid.NewGuid(), "orphan");
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Task_comments_are_audited_and_the_chain_stays_valid()
    {
        var (caseId, taskId) = await SeededCaseWithTaskAsync();
        await NewCommentService().AddAsync(caseId, taskId, "one");
        await NewCommentService().AddAsync(caseId, taskId, "two");

        await using var db = NewContext();
        (await db.AuditLog.CountAsync(a => a.EntityType == "ActionItemComment" && a.CaseNumber == "2026-01_Phishing_Wave"))
            .Should().Be(2);
        var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        (await db.ActionItemComments.AllAsync(c => c.RowHash != null)).Should().BeTrue();
    }

    /// <summary>Identity directory — resolves an id to itself for the author-name projection.</summary>
    private sealed class StubUserDirectory : IUserDirectory
    {
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<UserSummary> All() => Array.Empty<UserSummary>();
        public UserSummary? Resolve(string userId) => null;
        public string DisplayFor(string? userId) => userId ?? "—";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
    }


    public void Dispose() => _connection.Dispose();
}
