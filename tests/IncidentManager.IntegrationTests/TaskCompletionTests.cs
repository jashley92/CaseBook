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

    public void Dispose() => _connection.Dispose();
}
