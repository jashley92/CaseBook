using FluentAssertions;
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

/// <summary>INV-08: completing a task can put its result on the timeline, written once.</summary>
public sealed class TaskCompletionTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 16, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public TaskCompletionTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.IncidentCommander];
    }

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
        .Options;

    private CaseService NewService()
    {
        var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
        return new(new TestDbContextFactory(Options()), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());
    }

    private async Task<(CaseService Svc, Guid CaseId, Guid TaskId)> CaseWithTask()
    {
        var svc = NewService();
        var c = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Phish", Title = "Phishing", Classification = Classification.Incident,
            Severity = Severity.High, Origin = CaseOrigin.InternalDetection
        });
        await svc.AddActionItemAsync(c.Id, "Block look-alike domains", null, null);
        var taskId = (await svc.GetDetailAsync(c.Id))!.ActionItems.Single().Id;
        return (svc, c.Id, taskId);
    }

    [Fact]
    public async Task A_result_logged_on_completion_becomes_one_timeline_entry_dated_when_the_task_was_done()
    {
        var (svc, caseId, taskId) = await CaseWithTask();
        _clock.UtcNow = _clock.UtcNow.AddHours(5);
        var doneAt = _clock.UtcNow.AddHours(-2);

        await svc.CompleteActionItemAsync(caseId, taskId, doneAt, "All 12 domains blocked at the proxy", TimelineEntryType.Containment);

        var c = (await svc.GetDetailAsync(caseId))!;
        var task = c.ActionItems.Single();
        task.Status.Should().Be(ActionItemStatus.Done);
        task.CompletedAtUtc.Should().Be(doneAt);
        var entry = c.TimelineEntries.Single(e => e.ActionItemId == taskId);
        entry.Type.Should().Be(TimelineEntryType.Containment);
        entry.OccurredAtUtc.Should().Be(doneAt);
        entry.Description.Should().Be("All 12 domains blocked at the proxy");
        entry.Source.Should().Be("Task: Block look-alike domains");
        // Told once: the entry stands in for the task's "Task done" milestone.
        CaseMilestones.Project(c, new MilestoneLabels(x => "", s => "", p => "", m => ""))
            .Should().NotContain(m => m.Kind == MilestoneKind.TaskDone);
        await using var db = new AppDbContext(Options());
        (await db.ActionItemComments.SingleAsync(x => x.ActionItemId == taskId)).Body.Should().Be("Result: All 12 domains blocked at the proxy");
    }

    [Fact]
    public async Task Completing_without_a_result_or_logging_keeps_the_milestone()
    {
        var (svc, caseId, taskId) = await CaseWithTask();

        await svc.CompleteActionItemAsync(caseId, taskId, null, null, null);

        var c = (await svc.GetDetailAsync(caseId))!;
        c.TimelineEntries.Should().BeEmpty();
        CaseMilestones.Project(c, new MilestoneLabels(x => "", s => "", p => "", m => ""))
            .Should().ContainSingle(m => m.Kind == MilestoneKind.TaskDone);
    }

    [Fact]
    public async Task A_task_cannot_be_completed_in_the_future_or_logged_without_a_result()
    {
        var (svc, caseId, taskId) = await CaseWithTask();

        var future = () => svc.CompleteActionItemAsync(caseId, taskId, _clock.UtcNow.AddHours(1), null, null);
        var noResult = () => svc.CompleteActionItemAsync(caseId, taskId, null, " ", TimelineEntryType.Containment);

        await future.Should().ThrowAsync<ArgumentException>().WithMessage("*future*");
        await noResult.Should().ThrowAsync<ArgumentException>().WithMessage("*result*");
    }

    // --- INV-07: promoting a note or comment to the timeline ---

    [Fact]
    public async Task A_note_promoted_to_the_timeline_keeps_where_it_came_from()
    {
        var (svc, caseId, _) = await CaseWithTask();
        await svc.AddNoteAsync(caseId, "Session from AS9009 26h after the click");
        var note = (await svc.GetDetailAsync(caseId))!.Notes.Single();
        _clock.UtcNow = _clock.UtcNow.AddHours(3);

        await svc.PromoteToTimelineAsync(caseId, $"note:{note.Id}", TimelineEntryType.Analysis, note.CreatedAtUtc,
            "Session from AS9009, 26 hours after the click");

        var entry = (await svc.GetDetailAsync(caseId))!.TimelineEntries.Single();
        entry.PromotedFrom.Should().Be($"note:{note.Id}");
        entry.Source.Should().Be("Note");
        entry.OccurredAtUtc.Should().Be(note.CreatedAtUtc);
        entry.Description.Should().Be("Session from AS9009, 26 hours after the click");
        entry.BuildCanonicalContent().Should().Contain($"|from|note:{note.Id}");
    }

    [Fact]
    public async Task A_task_comment_can_be_promoted_but_not_one_from_another_case_or_as_a_decision()
    {
        var (svc, caseId, taskId) = await CaseWithTask();
        var comments = new ActionItemCommentService(new TestDbContextFactory(Options()), _user, _clock, new NullUserDirectory());
        var commentId = await comments.AddAsync(caseId, taskId, "Proxy change CHG-20931 raised");

        await svc.PromoteToTimelineAsync(caseId, $"taskcomment:{commentId}", TimelineEntryType.Containment, _clock.UtcNow, "Proxy change CHG-20931 raised");
        var decision = () => svc.PromoteToTimelineAsync(caseId, $"taskcomment:{commentId}", TimelineEntryType.Decision, _clock.UtcNow, "x");
        var elsewhere = () => svc.PromoteToTimelineAsync(caseId, $"comment:{Guid.NewGuid()}", TimelineEntryType.Analysis, _clock.UtcNow, "x");

        (await svc.GetDetailAsync(caseId))!.TimelineEntries.Single().Source.Should().Be("Task comment");
        await decision.Should().ThrowAsync<ArgumentException>();
        await elsewhere.Should().ThrowAsync<InvalidOperationException>();
    }

    private sealed class NullUserDirectory : IncidentManager.Application.Abstractions.IUserDirectory
    {
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<IncidentManager.Application.Abstractions.UserSummary> All() => [];
        public IncidentManager.Application.Abstractions.UserSummary? Resolve(string userId) => null;
        public string DisplayFor(string? userId) => userId ?? "—";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
    }

    public void Dispose() => _connection.Dispose();
}
