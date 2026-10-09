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

    // --- INV-13: task kinds ---

    [Fact]
    public async Task A_task_keeps_its_kind_and_the_kind_can_be_changed_on_edit()
    {
        var (svc, caseId, _) = await CaseWithTask();
        await svc.AddActionItemAsync(caseId, "Isolate FIN-WKS-07", null, null, TaskKind.Contain);
        var task = (await svc.GetDetailAsync(caseId))!.ActionItems.Single(t => t.Title == "Isolate FIN-WKS-07");
        task.Kind.Should().Be(TaskKind.Contain);

        await svc.UpdateActionItemAsync(caseId, task.Id, task.Title, null, null, ActionItemStatus.Open, null, TaskKind.Eradicate);
        (await svc.GetDetailAsync(caseId))!.ActionItems.Single(t => t.Id == task.Id).Kind.Should().Be(TaskKind.Eradicate);

        // Leaving the kind out of an edit keeps it.
        await svc.UpdateActionItemAsync(caseId, task.Id, "Isolate FIN-WKS-07 now", null, null, ActionItemStatus.Open, null);
        (await svc.GetDetailAsync(caseId))!.ActionItems.Single(t => t.Id == task.Id).Kind.Should().Be(TaskKind.Eradicate);
    }

    // --- INV-15: structured handoff ---

    [Fact]
    public async Task A_handoff_is_recorded_on_the_timeline_and_can_hand_over_my_open_tasks()
    {
        var (svc, caseId, _) = await CaseWithTask();
        await svc.AddActionItemAsync(caseId, "Mine, open", _user.UserId, null);
        await svc.AddActionItemAsync(caseId, "Someone else's", "other", null);

        var moved = await svc.HandOffAsync(caseId, "robin", "**Where it stands**\n\nContained; eradication next.", reassignMyOpenTasks: true);

        var c = (await svc.GetDetailAsync(caseId))!;
        moved.Should().Be(1);
        c.ActionItems.Single(t => t.Title == "Mine, open").Owner.Should().Be("robin");
        c.ActionItems.Single(t => t.Title == "Someone else's").Owner.Should().Be("other");
        var entry = c.TimelineEntries.Single(e => e.Type == TimelineEntryType.Handoff);
        entry.Kind.Should().Be(TimelineKind.Investigation);
        entry.Description.Should().Contain("eradication next");
    }

    [Fact]
    public async Task A_handoff_needs_someone_else_and_something_to_say()
    {
        var (svc, caseId, _) = await CaseWithTask();

        var toMe = () => svc.HandOffAsync(caseId, _user.UserId, "State", false);
        var empty = () => svc.HandOffAsync(caseId, "robin", " ", false);

        await toMe.Should().ThrowAsync<ArgumentException>();
        await empty.Should().ThrowAsync<ArgumentException>();
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

    // --- INV-09: the case brief ---

    [Fact]
    public async Task Each_brief_save_is_a_new_version_and_the_earlier_one_is_kept()
    {
        var (svc, caseId, _) = await CaseWithTask();

        await svc.ReviseBriefAsync(caseId, null, "Lure reached 12 Finance mailboxes", null, null, "Did the other two users have sessions?");
        var v1 = (await svc.GetDetailAsync(caseId))!.Briefs.Single();
        _clock.UtcNow = _clock.UtcNow.AddHours(2);
        await svc.ReviseBriefAsync(caseId, v1.Id, "Lure reached 12 Finance mailboxes; one mailbox accessed", "Opportunistic credential harvesting",
            "Session from AS9009", null);

        var briefs = (await svc.GetDetailAsync(caseId))!.Briefs;
        briefs.Should().HaveCount(2);
        var current = briefs.Single(b => b.IsCurrent);
        current.Version.Should().Be(2);
        current.SupersedesBriefId.Should().Be(v1.Id);
        current.OpenQuestions.Should().BeNull();
        briefs.Single(b => !b.IsCurrent).OpenQuestions.Should().Be("Did the other two users have sessions?");
        // INV-25: each version records the open tasks as its next steps.
        current.NextSteps.Should().Be("- Block look-alike domains");
    }

    // --- INV-28: tasks start where the work is ---

    [Fact]
    public async Task A_task_records_what_it_is_about_and_an_entry_is_anchored_at_its_first_version()
    {
        var (svc, caseId, _) = await CaseWithTask();
        var entity = await svc.AddEntityAsync(caseId, EntityType.Account, "CONTOSO\\jdoe", "Jane Doe", EntityDisposition.Unknown, null, "SIEM");
        await svc.AddTimelineEntryAsync(caseId, TimelineKind.Investigation, TimelineEntryType.Analysis, _clock.UtcNow.AddHours(-1),
            "Sign-ins from a foreign ASN", "an1");
        var entry = (await svc.GetDetailAsync(caseId))!.TimelineEntries.Single();
        await svc.EditInvestigationEntryAsync(caseId, entry.Id, TimelineEntryType.Analysis, entry.OccurredAtUtc, "Sign-ins from AS9009", "an1");
        var edited = (await svc.GetDetailAsync(caseId))!.TimelineEntries.Single(e => e.IsCurrent);
        edited.Id.Should().NotBe(entry.Id, "an edit is a new version");

        await svc.AddActionItemAsync(caseId, "Check her other sessions", null, null, about: $"entity:{entity}");
        await svc.AddActionItemAsync(caseId, "Pull the ASN's other sign-ins", null, null, about: $"entry:{edited.Id}");

        var tasks = (await svc.GetDetailAsync(caseId))!.ActionItems;
        tasks.Single(t => t.Title == "Check her other sessions").AboutRef.Should().Be($"entity:{entity}");
        tasks.Single(t => t.Title == "Pull the ASN's other sign-ins").AboutRef.Should().Be($"entry:{entry.Id}", "the first version, so the link survives edits");

        var elsewhere = () => svc.AddActionItemAsync(caseId, "Not ours", null, null, about: $"entity:{Guid.NewGuid()}");
        await elsewhere.Should().ThrowAsync<InvalidOperationException>();
        var nonsense = () => svc.AddActionItemAsync(caseId, "Garbled", null, null, about: "brief:xyz");
        await nonsense.Should().ThrowAsync<ArgumentException>();
    }

    // --- HR-17: small decay points ---

    [Fact]
    public async Task A_task_can_be_about_a_note_anchored_at_its_first_version()
    {
        var (svc, caseId, _) = await CaseWithTask();
        await svc.AddNoteAsync(caseId, "Vendor says they'll confirm by Friday.");
        var note = (await svc.GetDetailAsync(caseId))!.Notes.Single();
        await svc.EditNoteAsync(caseId, note.Id, "Vendor says they'll confirm by Friday 5pm.");
        var edited = (await svc.GetDetailAsync(caseId))!.Notes.Single(n => n.IsCurrent);

        await svc.AddActionItemAsync(caseId, "Chase the vendor on Friday", null, null, about: $"note:{edited.Id}");

        (await svc.GetDetailAsync(caseId))!.ActionItems.Single(t => t.Title == "Chase the vendor on Friday")
            .AboutRef.Should().Be($"note:{note.Id}", "the first version, so the link survives edits");
        var elsewhere = () => svc.AddActionItemAsync(caseId, "Not ours", null, null, about: $"note:{Guid.NewGuid()}");
        await elsewhere.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Cancelling_a_task_keeps_the_reason_given()
    {
        var (svc, caseId, taskId) = await CaseWithTask();
        var t = (await svc.GetDetailAsync(caseId))!.ActionItems.Single(x => x.Id == taskId);

        await svc.UpdateActionItemAsync(caseId, taskId, t.Title, t.Owner, t.DueAtUtc, ActionItemStatus.Cancelled, t.Description,
            cancelReason: "Covered by the tenant-wide session revoke");
        await svc.UpdateActionItemAsync(caseId, taskId, t.Title + " (renamed)", t.Owner, t.DueAtUtc, ActionItemStatus.Cancelled, t.Description,
            cancelReason: "ignored: it was already cancelled");

        await using var db = new AppDbContext(Options());
        (await db.ActionItemComments.SingleAsync(x => x.ActionItemId == taskId)).Body
            .Should().Be("Cancelled: Covered by the tenant-wide session revoke");
    }

    // --- INV-25: next steps are tasks ---

    [Fact]
    public async Task An_open_question_is_followed_up_as_a_task_linked_to_the_brief()
    {
        var (svc, caseId, _) = await CaseWithTask();
        await svc.ReviseBriefAsync(caseId, null, "Lure reached Finance", null, null, "- Did the other two users have sessions?");
        var brief = (await svc.GetDetailAsync(caseId))!.Briefs.Single();

        await svc.RaiseTaskFromQuestionAsync(caseId, "Did the other two users have sessions?");

        var task = (await svc.GetDetailAsync(caseId))!.ActionItems.Single(t => t.RaisedFromBriefId is not null);
        task.Should().Match<IncidentManager.Domain.Entities.ActionItem>(t => t.Title == "Did the other two users have sessions?" && t.RaisedFromBriefId == brief.Id
                                             && t.Description == "Raised from an open question in the brief (v1)." && t.IsOpen);
        var again = () => svc.RaiseTaskFromQuestionAsync(caseId, "did the other two users have sessions?");
        await again.Should().ThrowAsync<InvalidOperationException>("an open task already follows it up");
    }

    [Fact]
    public async Task A_question_from_the_composer_joins_the_brief_and_can_be_followed_up_at_once(/* RD-07 */)
    {
        var (svc, caseId, _) = await CaseWithTask();
        await svc.ReviseBriefAsync(caseId, null, "Lure reached Finance", "Opportunistic", "- One session from a foreign ASN", "- Did the lure reach other teams?");

        await svc.AddOpenQuestionAsync(caseId, "Did the other two users' credentials get used?", followUp: true);

        var c = (await svc.GetDetailAsync(caseId))!;
        var brief = c.Briefs.Single(b => b.IsCurrent);
        brief.Version.Should().Be(2);
        brief.OpenQuestions.Should().Be("- Did the lure reach other teams?\n- Did the other two users' credentials get used?");
        brief.WorkingAssessment.Should().Be("Opportunistic", "the other parts carry over");
        brief.Known.Should().Be("- One session from a foreign ASN");
        c.ActionItems.Single(t => t.RaisedFromBriefId == brief.Id).Title.Should().Be("Did the other two users' credentials get used?");

        var again = () => svc.AddOpenQuestionAsync(caseId, "did the other two users' credentials get used?", followUp: false);
        await again.Should().ThrowAsync<InvalidOperationException>("it's already open");
        var empty = () => svc.AddOpenQuestionAsync(caseId, "  ", followUp: false);
        await empty.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task A_question_is_one_line_of_markdown_and_its_task_title_is_plain_text()
    {
        var (svc, caseId, _) = await CaseWithTask();
        await svc.ReviseBriefAsync(caseId, null, "Lure reached Finance", null, null, null);

        await svc.AddOpenQuestionAsync(caseId, "Did **both**\n  users reuse `P@ss`?", followUp: true);

        var c = (await svc.GetDetailAsync(caseId))!;
        var brief = c.Briefs.Single(b => b.IsCurrent);
        brief.OpenQuestions.Should().Be("- Did **both** users reuse `P@ss`?");
        // The brief pairs a question with its task by the question's plain text, so the two must match.
        c.ActionItems.Single(t => t.RaisedFromBriefId == brief.Id).Title.Should().Be("Did both users reuse P@ss?");
    }

    [Fact]
    public async Task A_decision_saves_with_its_follow_ups_in_one_go(/* RD-09 */)
    {
        var (svc, caseId, _) = await CaseWithTask();
        await svc.ReviseBriefAsync(caseId, null, "Lure reached Finance", "Opportunistic", "- One session from a foreign ASN", null);
        var other = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "VPN Travel", Title = "Impossible-travel VPN sign-in", Classification = Classification.AdverseEvent,
            Severity = Severity.Low, Origin = CaseOrigin.InternalDetection
        });
        var follow = new EntryFollowUps(
            Tasks: [new FollowUpTask("Block 203.0.113.66 at the VPN gateway", "analyst1", TaskKind.Contain)],
            Question: "Is 203.0.113.66 one of our VPN provider's addresses?", QuestionTask: true,
            KnownLine: "203.0.113.66 was used again on 4 Oct against a second account.",
            LinkCaseId: other.Id, LinkType: CaseLinkType.RelatedTo);

        await svc.AddTimelineEntryAsync(caseId, TimelineKind.Investigation, TimelineEntryType.Decision, _clock.UtcNow,
            "Block 203.0.113.66 for all users.", null, decision: new CaseService.DecisionDetails("Malicious here and seen again today.", null, "IC"),
            followUps: follow);

        var c = (await svc.GetDetailAsync(caseId))!;
        var decision = c.TimelineEntries.Single(e => e.Type == TimelineEntryType.Decision);
        c.ActionItems.Single(t => t.Title.StartsWith("Block 203", StringComparison.Ordinal)).AboutRef.Should().Be($"entry:{decision.Id}");
        var brief = c.Briefs.Single(b => b.IsCurrent);
        brief.Version.Should().Be(2, "the question and the Known line make one new version");
        brief.Known.Should().EndWith("- 203.0.113.66 was used again on 4 Oct against a second account.");
        brief.OpenQuestions.Should().Be("- Is 203.0.113.66 one of our VPN provider's addresses?");
        c.ActionItems.Should().Contain(t => t.RaisedFromBriefId == brief.Id);
        (await svc.GetCaseLinksAsync(caseId)).Should().ContainSingle(l => l.OtherCaseId == other.Id);

        var bad = () => svc.AddTimelineEntryAsync(caseId, TimelineKind.Investigation, TimelineEntryType.Analysis, _clock.UtcNow,
            "Second entry", null, followUps: new EntryFollowUps(Tasks: [new FollowUpTask("  ")]));
        await bad.Should().ThrowAsync<ArgumentException>();
        (await svc.GetDetailAsync(caseId))!.TimelineEntries.Should().NotContain(e => e.Description == "Second entry", "nothing is written when a follow-up is invalid");
    }

    [Fact]
    public async Task Completing_a_task_can_add_its_finding_to_Known(/* RD-10 */)
    {
        var (svc, caseId, taskId) = await CaseWithTask();
        await svc.ReviseBriefAsync(caseId, null, "Lure reached Finance", null, "- One session from a foreign ASN", null);

        await svc.CompleteActionItemAsync(caseId, taskId, null, "All 12 domains blocked at the proxy.", null,
            knownLine: "The 12 look-alike domains are blocked at the proxy.");

        var c = (await svc.GetDetailAsync(caseId))!;
        c.ActionItems.Single(t => t.Id == taskId).Status.Should().Be(ActionItemStatus.Done);
        var brief = c.Briefs.Single(b => b.IsCurrent);
        brief.Version.Should().Be(2);
        brief.Known.Should().Be("- One session from a foreign ASN\n- The 12 look-alike domains are blocked at the proxy.");
    }

    // --- HR-02: answers stay with their questions ---

    private async Task<(CaseService Svc, Guid CaseId, Guid QuestionTaskId, Guid PlainTaskId)> CaseWithQuestionTask()
    {
        var (svc, caseId, plainId) = await CaseWithTask();
        await svc.ReviseBriefAsync(caseId, null, "Lure reached Finance", null, null, "- Were any vendor banking changes requested?");
        await svc.RaiseTaskFromQuestionAsync(caseId, "Were any vendor banking changes requested?");
        var q = (await svc.GetDetailAsync(caseId))!.ActionItems.Single(t => t.RaisedFromBriefId is not null);
        return (svc, caseId, q.Id, plainId);
    }

    [Fact]
    public async Task A_question_task_cannot_be_done_without_an_answer_by_any_path()
    {
        var (svc, caseId, qId, _) = await CaseWithQuestionTask();

        var complete = () => svc.CompleteActionItemAsync(caseId, qId, null, "  ", null);
        await complete.Should().ThrowAsync<InvalidOperationException>().WithMessage("*Say what was found*");
        var status = () => svc.SetActionItemStatusAsync(caseId, qId, ActionItemStatus.Done);
        await status.Should().ThrowAsync<InvalidOperationException>();
        var edit = () => svc.UpdateActionItemAsync(caseId, qId, "Were any vendor banking changes requested?", null, null,
            ActionItemStatus.Done, null);
        await edit.Should().ThrowAsync<InvalidOperationException>();

        (await svc.GetDetailAsync(caseId))!.ActionItems.Single(t => t.Id == qId).IsOpen.Should().BeTrue();
    }

    [Fact]
    public async Task An_answer_is_kept_with_who_did_it_and_survives_a_reopen()
    {
        var (svc, caseId, qId, plainId) = await CaseWithQuestionTask();

        await svc.CompleteActionItemAsync(caseId, qId, null, "None. AP confirmed no change requests.", null, doneBy: "Accounts Payable lead");
        await svc.SetActionItemStatusAsync(caseId, plainId, ActionItemStatus.Done);   // a plain task needs no result

        var c = (await svc.GetDetailAsync(caseId))!;
        c.ActionItems.Single(t => t.Id == qId).CompletedBy.Should().Be("Accounts Payable lead");
        c.ActionItems.Single(t => t.Id == plainId).CompletedBy.Should().Be(_user.UserId);
        var results = await svc.GetTaskResultsAsync(caseId);
        results[qId].Text.Should().Be("None. AP confirmed no change requests.");
        results.Should().NotContainKey(plainId);

        // Reopened, then done again from the status menu: the earlier answer still counts and stays on record.
        await svc.SetActionItemStatusAsync(caseId, qId, ActionItemStatus.InProgress);
        (await svc.GetDetailAsync(caseId))!.ActionItems.Single(t => t.Id == qId).CompletedBy.Should().BeNull();
        await svc.SetActionItemStatusAsync(caseId, qId, ActionItemStatus.Done);
        (await svc.GetTaskResultsAsync(caseId))[qId].Text.Should().Be("None. AP confirmed no change requests.");
    }

    [Fact]
    public async Task A_brief_saved_from_an_older_version_is_refused_and_an_empty_one_is_rejected()
    {
        var (svc, caseId, _) = await CaseWithTask();
        await svc.ReviseBriefAsync(caseId, null, "First", null, null, null);

        var stale = () => svc.ReviseBriefAsync(caseId, null, "Written without seeing the first", null, null, null);
        var current = (await svc.GetDetailAsync(caseId))!.Briefs.Single().Id;
        var empty = () => svc.ReviseBriefAsync(caseId, current, " ", null, "", null);

        await stale.Should().ThrowAsync<StaleEditException>();
        await empty.Should().ThrowAsync<ArgumentException>();
    }

    // --- INV-36: the summary is the brief's first part, versioned with it ---

    [Fact]
    public async Task The_summary_is_versioned_with_the_brief_whichever_way_it_changes()
    {
        var created = await NewService().CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Summ", Title = "Summary history", Classification = Classification.Incident,
            Severity = Severity.High, Summary = "Lure reached Finance."
        });
        var svc = NewService();
        var v1 = (await svc.GetDetailAsync(created.Id))!.Briefs.Single();
        v1.Summary.Should().Be("Lure reached Finance.", "the summary written at intake is version 1");

        await svc.ReviseBriefAsync(created.Id, v1.Id, "Lure reached 12 Finance mailboxes; one accessed.", "Opportunistic", null, null);
        var afterRevise = await svc.GetDetailAsync(created.Id);
        afterRevise!.Summary.Should().Be("Lure reached 12 Finance mailboxes; one accessed.", "the report reads the case's summary");

        // A summary edit made through the details editor (or any other path) is a version too, carrying the rest.
        await svc.UpdateDetailsAsync(created.Id, "Summary history", "Breach confirmed: NPI of 1,450 residents.", null, null, null,
            afterRevise.DetectedAtUtc!.Value, null);
        var briefs = (await svc.GetDetailAsync(created.Id))!.Briefs.OrderBy(b => b.Version).ToList();
        briefs.Select(b => b.Summary).Should().Equal(
            "Lure reached Finance.", "Lure reached 12 Finance mailboxes; one accessed.", "Breach confirmed: NPI of 1,450 residents.");
        briefs.Should().ContainSingle(b => b.IsCurrent).Which.WorkingAssessment.Should().Be("Opportunistic");

        // Saving details without touching the summary adds no version.
        await svc.UpdateDetailsAsync(created.Id, "Retitled", "Breach confirmed: NPI of 1,450 residents.", null, null, null,
            afterRevise.DetectedAtUtc!.Value, null);
        (await svc.GetDetailAsync(created.Id))!.Briefs.Should().HaveCount(3);
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
