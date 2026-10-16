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

/// <summary>
/// BUG-577: a task's due is bounded where it's typed (years 2 to 9998). A due of 9999-12-31 sat at the end of the
/// calendar, where the agenda feed, the reminders and every other reader that adds to it threw. Each way a due comes in
/// is checked: a new task, an edit, an import, and the tasks saved with a timeline entry.
/// </summary>
public sealed class TaskDueBoundsTests : IDisposable
{
    private static readonly DateTimeOffset EndOf9999 = new(9999, 12, 31, 23, 59, 0, TimeSpan.Zero);

    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 16, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public TaskDueBoundsTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.IncidentCommander];
    }

    public void Dispose() => _connection.Dispose();

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
        .Options;

    private async Task<(CaseService Svc, Guid CaseId)> NewCase()
    {
        using (var db = new AppDbContext(Options())) db.Database.EnsureCreated();
        var svc = new CaseService(new TestDbContextFactory(Options()), _user, _clock, new CaseNumberGenerator(new AppDbContext(Options())),
            new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());
        var c = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Phish", Title = "Phishing", Classification = Classification.Incident,
            Severity = Severity.High, Origin = CaseOrigin.InternalDetection
        });
        return (svc, c.Id);
    }

    [Fact]
    public async Task A_new_task_due_at_the_end_of_the_calendar_is_refused_in_words()
    {
        var (svc, caseId) = await NewCase();

        await svc.Invoking(s => s.AddActionItemAsync(caseId, "Rotate keys", null, EndOf9999))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*years 2 to 9998*");
        await svc.Invoking(s => s.AddActionItemAsync(caseId, "Rotate keys", null, new DateTimeOffset(1, 1, 1, 0, 0, 0, TimeSpan.Zero)))
            .Should().ThrowAsync<ArgumentException>();
        (await svc.GetDetailAsync(caseId))!.ActionItems.Should().BeEmpty();

        // The last day and the first take one; so does no due at all.
        await svc.AddActionItemAsync(caseId, "Last", null, CaseService.LatestDueUtc);
        await svc.AddActionItemAsync(caseId, "First", null, CaseService.EarliestDueUtc);
        await svc.AddActionItemAsync(caseId, "Undated", null, null);
        (await svc.GetDetailAsync(caseId))!.ActionItems.Should().HaveCount(3);
    }

    [Fact]
    public async Task An_edit_that_sets_a_due_out_of_range_is_refused_but_one_stored_before_the_bound_doesnt_stop_other_edits()
    {
        var (svc, caseId) = await NewCase();
        await svc.AddActionItemAsync(caseId, "Rotate keys", null, _clock.UtcNow.AddDays(1));
        var task = (await svc.GetDetailAsync(caseId))!.ActionItems.Single();

        await svc.Invoking(s => s.UpdateActionItemAsync(caseId, task.Id, task.Title, null, EndOf9999, ActionItemStatus.Open, null))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*years 2 to 9998*");
        (await svc.GetDetailAsync(caseId))!.ActionItems.Single().DueAtUtc.Should().Be(_clock.UtcNow.AddDays(1));

        // A due saved before v1.6.12 at 9999-12-31: renaming the task keeps it, rather than refusing the rename.
        using (var db = new AppDbContext(Options()))
        {
            var row = await db.ActionItems.SingleAsync(a => a.Id == task.Id);
            row.DueAtUtc = EndOf9999;
            await db.SaveChangesAsync();
        }
        await svc.UpdateActionItemAsync(caseId, task.Id, "Rotate every key", null, EndOf9999, ActionItemStatus.Open, null);
        var after = (await svc.GetDetailAsync(caseId))!.ActionItems.Single();
        after.Title.Should().Be("Rotate every key");
        after.DueAtUtc.Should().Be(EndOf9999);
    }

    [Fact]
    public async Task An_import_with_one_due_out_of_range_saves_none_of_its_tasks()
    {
        var (svc, caseId) = await NewCase();
        // More than one batch, the bad due in the last: checked before the first batch is saved.
        var items = Enumerable.Range(1, CaseService.EntitiesPerSave + 1)
            .Select(i => ($"Task {i}", (string?)null, (DateTimeOffset?)_clock.UtcNow.AddDays(i))).ToList();
        items[^1] = ("Far off", null, EndOf9999);
        var saved = 0;

        await svc.Invoking(s => s.AddImportedActionItemsAsync(caseId, items, n => saved += n))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*\"Far off\"*");
        saved.Should().Be(0);
        (await svc.GetDetailAsync(caseId))!.ActionItems.Should().BeEmpty();
    }

    [Fact]
    public async Task A_task_saved_with_a_timeline_entry_is_bounded_too()
    {
        var (svc, caseId) = await NewCase();
        var followUps = new EntryFollowUps(Tasks: [new FollowUpTask("Disable the account", DueAtUtc: EndOf9999)]);

        await svc.Invoking(s => s.AddTimelineEntryAsync(caseId, TimelineKind.Investigation, TimelineEntryType.Analysis,
                _clock.UtcNow.AddHours(-1), "Checked j.morales sign-ins", null, followUps: followUps))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*\"Disable the account\"*");
        var c = (await svc.GetDetailAsync(caseId))!;
        c.ActionItems.Should().BeEmpty();
        c.TimelineEntries.Should().BeEmpty("the entry and its tasks are one save");
    }
}
