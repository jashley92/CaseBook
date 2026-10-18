using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-23: a finding saved from the composer answers one of the brief's open questions. One save writes the entry, the
/// question's task completed and its result, linked by the entry's task id; a question no task followed up gets one, raised
/// and completed; a question answered or followed up by someone else since the picker showed it is refused with nothing
/// written; need-to-know holds. Runs on SQLite always and on SQL Server when <c>CASEBOOK_TEST_SQL</c> is set.
/// </summary>
public sealed class FindingAnswersQuestionTests
{
    private const string Question = "Did the attacker reach the **payroll** share?";
    private const string Finding = "No: the share's access log shows no reads from the compromised account.";

    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "ic1", RoleSet = [AppRole.SysAdmin] };

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));

    private CaseService NewService(TestDatabase database, TestCurrentUser? user = null) =>
        new(database.Factory(), user ?? _user, _clock, new CaseNumberGenerator(database.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private async Task<Guid> SeedAsync(CaseService svc, bool withTask)
    {
        var id = (await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Answer", Title = "Account takeover", Classification = Classification.Incident, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, DetectedAtUtc = _clock.UtcNow.AddDays(-1)
        })).Id;
        await svc.AddOpenQuestionAsync(id, Question, followUp: withTask);
        _clock.UtcNow = _clock.UtcNow.AddMinutes(10);
        return id;
    }

    private static Task<Guid> AddFindingAsync(CaseService svc, Guid id, QuestionAnswer answer, DateTimeOffset at, Guid? linkCase = null) =>
        svc.AddTimelineEntryAsync(id, TimelineKind.Investigation, TimelineEntryType.Analysis, at, Finding, null,
            followUps: new EntryFollowUps(LinkCaseId: linkCase, Answers: answer));

    private static async Task<List<ActionItemComment>> ResultsAsync(TestDatabase database, Guid caseId)
    {
        await using var db = database.NewContext();
        return await db.ActionItemComments.AsNoTracking().Where(x => x.CaseId == caseId).ToListAsync();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task One_save_writes_the_entry_the_task_completion_and_its_result(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await SeedAsync(svc, withTask: true);
        var before = (await svc.GetDetailAsync(id))!;
        var offered = OpenQuestionAnswers.Answerable(before).Should().ContainSingle().Subject;
        offered.TaskId.Should().NotBeNull("the question was followed up as a task");
        var at = _clock.UtcNow.AddMinutes(-5);

        var entryId = await AddFindingAsync(svc, id, offered, at);

        var c = (await svc.GetDetailAsync(id))!;
        var task = c.ActionItems.Single(t => t.Id == offered.TaskId);
        task.Status.Should().Be(ActionItemStatus.Done);
        task.CompletedAtUtc.Should().Be(at);
        task.CompletedBy.Should().Be("ic1");
        c.TimelineEntries.Single(e => e.Id == entryId).ActionItemId.Should().Be(task.Id);
        (await ResultsAsync(database, id)).Should().ContainSingle().Which.Body.Should().Be(TaskResults.Body(Finding));
        OpenQuestionAnswers.Answerable(c).Should().BeEmpty("the question is answered");
        // The brief and Briefing pair the question with its task as before, so they show the answer (HR-02).
        c.TasksFollowingUp(IncidentManager.Application.Content.MarkdownService.PlainLine(Question)).Should().ContainSingle()
            .Which.Id.Should().Be(task.Id);

        // A link this save can't make refuses the whole save: the answer is written with the entry or not at all.
        var other = await SeedAsync(svc, withTask: true);
        var otherQ = OpenQuestionAnswers.Answerable((await svc.GetDetailAsync(other))!).Single();
        await svc.Invoking(s => AddFindingAsync(s, other, otherQ, _clock.UtcNow, linkCase: Guid.NewGuid()))
            .Should().ThrowAsync<InvalidOperationException>();
        var untouched = (await svc.GetDetailAsync(other))!;
        untouched.ActionItems.Single().Status.Should().Be(ActionItemStatus.Open);
        untouched.TimelineEntries.Should().NotContain(e => e.Kind == TimelineKind.Investigation && e.Description == Finding);
        (await ResultsAsync(database, other)).Should().BeEmpty();

        await using var db = database.NewContext();
        _hasher.VerifyChain(await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_question_with_no_task_gets_one_raised_and_completed(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await SeedAsync(svc, withTask: false);
        var offered = OpenQuestionAnswers.Answerable((await svc.GetDetailAsync(id))!).Should().ContainSingle().Subject;
        offered.TaskId.Should().BeNull();

        var entryId = await AddFindingAsync(svc, id, offered, _clock.UtcNow);

        var c = (await svc.GetDetailAsync(id))!;
        var task = c.ActionItems.Should().ContainSingle().Subject;
        task.FollowsUpQuestion.Should().BeTrue();
        task.Title.Should().Be("Did the attacker reach the payroll share?", "titled as the brief pairs it (WF-25)");
        task.Status.Should().Be(ActionItemStatus.Done);
        c.TimelineEntries.Single(e => e.Id == entryId).ActionItemId.Should().Be(task.Id);
        (await ResultsAsync(database, id)).Should().ContainSingle().Which.ActionItemId.Should().Be(task.Id);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_question_answered_or_followed_up_meanwhile_is_refused_with_nothing_written(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var colleague = NewService(database, new TestCurrentUser { UserId = "analyst2", RoleSet = [AppRole.SysAdmin] });

        // Answered from the task (Mark done) after the picker showed it.
        var id = await SeedAsync(svc, withTask: true);
        var picked = OpenQuestionAnswers.Answerable((await svc.GetDetailAsync(id))!).Single();
        await colleague.CompleteActionItemAsync(id, picked.TaskId!.Value, null, "Yes, two files were read.", null);
        await svc.Invoking(s => AddFindingAsync(s, id, picked, _clock.UtcNow))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("*answered that question while you were writing*");
        var c = (await svc.GetDetailAsync(id))!;
        c.TimelineEntries.Should().NotContain(e => e.Description == Finding);
        (await ResultsAsync(database, id)).Should().ContainSingle().Which.Body.Should().Be(TaskResults.Body("Yes, two files were read."));

        // Picked with no task, then a colleague followed it up: theirs is the task to complete, not a second one.
        var second = await SeedAsync(svc, withTask: false);
        var noTask = OpenQuestionAnswers.Answerable((await svc.GetDetailAsync(second))!).Single();
        await colleague.RaiseTaskFromQuestionAsync(second, IncidentManager.Application.Content.MarkdownService.PlainLine(Question));
        await svc.Invoking(s => AddFindingAsync(s, second, noTask, _clock.UtcNow))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("*followed that question up with a task*");
        (await svc.GetDetailAsync(second))!.ActionItems.Should().ContainSingle().Which.Status.Should().Be(ActionItemStatus.Open);

        // And a question taken out of the brief meanwhile.
        var third = await SeedAsync(svc, withTask: false);
        var gone = OpenQuestionAnswers.Answerable((await svc.GetDetailAsync(third))!).Single();
        var brief = (await svc.GetDetailAsync(third))!.Briefs.Single(b => b.IsCurrent);
        await colleague.ReviseBriefAsync(third, brief.Id, brief.Summary, "Contained", brief.Known, null);
        await svc.Invoking(s => AddFindingAsync(s, third, gone, _clock.UtcNow))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("That question is no longer open in the brief*");
        (await svc.GetDetailAsync(third))!.ActionItems.Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Need_to_know_holds_and_a_task_from_another_case_is_refused(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await SeedAsync(svc, withTask: true);
        var picked = OpenQuestionAnswers.Answerable((await svc.GetDetailAsync(id))!).Single();
        await svc.SetRestrictedAsync(id, true, "Insider matter");

        var outsider = NewService(database, new TestCurrentUser { UserId = "analyst-unrelated", RoleSet = [AppRole.Analyst] });
        await outsider.Invoking(s => AddFindingAsync(s, id, picked, _clock.UtcNow))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("Case not found or not accessible.");
        (await svc.GetDetailAsync(id))!.ActionItems.Single().Status.Should().Be(ActionItemStatus.Open);

        // Another case's task id, on a case the caller can see, isn't completed from here.
        var other = await SeedAsync(svc, withTask: false);
        await svc.Invoking(s => AddFindingAsync(s, other, picked, _clock.UtcNow))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("The task for that question isn't on this case.");
        (await svc.GetDetailAsync(id))!.ActionItems.Single().Status.Should().Be(ActionItemStatus.Open);
        (await ResultsAsync(database, id)).Should().BeEmpty();
    }
}
