using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Notifications;
using IncidentManager.Application.Security;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Web.BackgroundJobs;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-10: the retention review lists closed, not-archived cases past Retention:CaseYears with their legal hold, open
/// improvement actions and unreported deadlines; archives at most 25 picked cases through the case's own archive action
/// (which still refuses a hold or a running deadline); the nightly count only counts; and the monthly email to Legal goes
/// once a month, only when it's on, something is due and the send succeeded. On both providers.
/// </summary>
public sealed class RetentionReviewTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 3, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _admin = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };
    private readonly StubDeadlineSettings _deadlineSettings = new();
    private readonly TestOptionsMonitor<CaseRetentionOptions> _retention = new(new CaseRetentionOptions { CaseYears = 7 });

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _admin, _clock, new CaseChangeNotifier()));

    private sealed class StubDeadlineSettings : INotificationDeadlineSettingsProvider
    {
        public NotificationDeadlineSettings Current { get; set; } = new(true, NotificationStartBasis.Determination, 72, 80);
    }

    private RetentionReviewService Service(TestDatabase database, ICurrentUser? user = null)
    {
        user ??= _admin;
        var rules = new NotificationRuleService(database.Factory(), _admin, _clock);
        var cases = new CaseService(database.Factory(), user, _clock, new CaseNumberGenerator(database.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new StageGateEvaluator(), new TestSlaTargets(), notifySettings: _deadlineSettings, notifyRules: rules);
        return new RetentionReviewService(database.Factory(), user, _clock, cases, _retention,
            new NotificationDeadlineService(database.Factory(), _deadlineSettings, rules, _clock));
    }

    private sealed record Seeded(Guid Due, Guid Held, Guid Deadline, Guid Restricted, Guid Recent, Guid Open, Guid Archived, Guid Exercise);

    /// <summary>
    /// Eight cases: due (closed 8 years ago, two open improvement actions and a completed one), held (closed 8 years ago,
    /// under a legal hold), deadline (a material breach closed 8 years ago whose NY notice was never recorded), restricted
    /// (closed 8 years ago, nobody's but ic1's), recent (closed 2 years ago), open (opened 9 years ago, never closed),
    /// archived (closed 9 years ago, already archived), and an exercise closed 9 years ago.
    /// </summary>
    private async Task<Seeded> SeedAsync(TestDatabase database)
    {
        var old = _clock.UtcNow.AddYears(-8);
        await using var db = database.NewContext();
        db.DataElements.Add(new DataElement { Key = "SSN", Label = "Social Security number", NotificationJurisdictions = "NY",
            IsActive = true, IsSystem = false, CreatedBy = "system", CreatedAtUtc = old.AddDays(-30) });
        db.NotificationRules.Add(new NotificationRule { Code = "NY", Label = "New York (NYDFS Part 500)", WindowHours = 72, IsActive = true,
            CreatedBy = "system", CreatedAtUtc = old.AddDays(-30) });

        Case Closed(int seq, string name, DateTimeOffset closedAt, bool exercise = false, Classification classification = Classification.Incident)
        {
            var c = Case.Open(2018, seq, name, name + " title", classification, Severity.Medium, CaseOrigin.InternalDetection, "ic1",
                closedAt.AddDays(-10), isExercise: exercise);
            c.ChangePhase(CasePhase.Closed, "Done", "ic1", closedAt);
            db.Cases.Add(c);
            return c;
        }

        var due = Closed(1, "Due", old);
        db.ImprovementActions.AddRange(
            new ImprovementAction { CaseId = due.Id, Title = "MFA on the VPN", CreatedBy = "ic1", CreatedAtUtc = old },
            new ImprovementAction { CaseId = due.Id, Title = "Mail rule sweep", CreatedBy = "ic1", CreatedAtUtc = old, Status = ImprovementActionStatus.InProgress },
            new ImprovementAction { CaseId = due.Id, Title = "Phish training", CreatedBy = "ic1", CreatedAtUtc = old,
                Status = ImprovementActionStatus.Completed, ClosedAtUtc = old.AddDays(5), OutcomeNote = "Done" });
        var held = Closed(2, "Held", old);
        held.LegalHold = true;

        var breach = Case.Open(2018, 3, "Breach", "Breach title", Classification.Breach, Severity.High, CaseOrigin.InternalDetection, "ic1",
            old.AddDays(-10));
        breach.SetImpactAssessment(500, ["SSN"], "NY", "ic1", old.AddDays(-9));
        breach.RecordMateriality(MaterialityStatus.Material, "Disclosure Committee", old.AddDays(-8), "Likely harm.", "ic1", old.AddDays(-8));
        breach.ChangePhase(CasePhase.Closed, "Done", "ic1", old);
        db.Cases.Add(breach);

        var restricted = Closed(4, "Restricted", old);
        restricted.IsRestricted = true;
        restricted.Assign("ic1", "IC One", CaseAssignmentRole.IncidentCommander, "ic1", old.AddDays(-1));
        var recent = Closed(5, "Recent", _clock.UtcNow.AddYears(-2));
        var open = Case.Open(2017, 6, "Open", "Still open", Classification.Incident, Severity.Low, CaseOrigin.InternalDetection, "ic1",
            _clock.UtcNow.AddYears(-9));
        db.Cases.Add(open);
        var archived = Closed(7, "Archived", _clock.UtcNow.AddYears(-9));
        archived.Archive("admin1", _clock.UtcNow.AddYears(-1));
        var exercise = Closed(8, "Drill", _clock.UtcNow.AddYears(-9), exercise: true);
        await db.SaveChangesAsync();
        return new Seeded(due.Id, held.Id, breach.Id, restricted.Id, recent.Id, open.Id, archived.Id, exercise.Id);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Lists_closed_cases_past_retention_with_their_hold_actions_and_deadlines(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);

        var review = await Service(database).BuildAsync();

        review.Off.Should().BeFalse();
        review.CutoffUtc.Should().Be(_clock.UtcNow.AddYears(-7));
        review.Rows.Select(r => r.CaseId).Should().BeEquivalentTo([s.Due, s.Held, s.Deadline, s.Restricted],
            "closed before the cut-off and not archived; not the recent, open, archived or exercise ones");

        var due = review.Rows.Single(r => r.CaseId == s.Due);
        (due.LegalHold, due.OpenImprovementActions, due.UnreportedDeadlines.Count, due.CanArchive).Should().Be((false, 2, 0, true),
            "open and in-progress actions count; a completed one doesn't, and none of them blocks archiving");

        var held = review.Rows.Single(r => r.CaseId == s.Held);
        held.LegalHold.Should().BeTrue();
        held.CanArchive.Should().BeFalse();
        held.Blocker.Should().Be("Under legal hold");

        var deadline = review.Rows.Single(r => r.CaseId == s.Deadline);
        deadline.UnreportedDeadlines.Should().ContainSingle(d => d.Jurisdiction.Contains("New York") && d.State == IncidentManager.Application.Sla.SlaState.Breached);
        deadline.CanArchive.Should().BeFalse();
        deadline.Blocker.Should().Be("Regulatory notice not recorded");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_administrator_sees_only_the_cases_their_need_to_know_allows(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);
        // Administer without ViewAllCases or ViewRestricted: the restricted case, nobody's but ic1's, isn't theirs to see.
        var narrow = new TestCurrentUser { UserId = "ops1", PermissionSet = [Permission.ViewCases, Permission.Administer] };

        var review = await Service(database, narrow).BuildAsync();

        review.Rows.Select(r => r.CaseId).Should().NotContain(s.Restricted).And.Contain(s.Due);
        var archive = await Service(database, narrow).ArchiveAsync([s.Restricted]);
        archive.Should().ContainSingle().Which.Outcome.Should().Be(RetentionArchiveOutcome.NoLongerDue, "hidden looks like not there");
        await using var db = database.NewContext();
        (await db.Cases.SingleAsync(c => c.Id == s.Restricted)).IsArchived.Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Only_an_administrator_reviews_or_archives(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);
        var manager = new TestCurrentUser { UserId = "mgr1", RoleSet = [AppRole.Manager] };

        await Service(database, manager).Invoking(x => x.BuildAsync()).Should().ThrowAsync<ForbiddenException>();
        await Service(database, manager).Invoking(x => x.ArchiveAsync([s.Due])).Should().ThrowAsync<ForbiddenException>();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Zero_years_turns_the_review_off(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);
        _retention.CurrentValue = new CaseRetentionOptions { CaseYears = 0 };

        var review = await Service(database).BuildAsync();

        review.Off.Should().BeTrue();
        review.Rows.Should().BeEmpty();
        await Service(database).Invoking(x => x.ArchiveAsync([s.Due])).Should().ThrowAsync<InvalidOperationException>().WithMessage("*off*");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Archives_the_picked_cases_and_reports_the_ones_the_case_refuses(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);

        var results = await Service(database).ArchiveAsync([s.Due, s.Held, s.Deadline, s.Recent, s.Due]);

        results.Select(r => (r.CaseId, r.Outcome)).Should().Equal(
            (s.Due, RetentionArchiveOutcome.Archived),
            (s.Held, RetentionArchiveOutcome.Refused),
            (s.Deadline, RetentionArchiveOutcome.Refused),
            (s.Recent, RetentionArchiveOutcome.NoLongerDue));
        results.Single(r => r.CaseId == s.Held).Detail.Should().Contain("legal hold");
        results.Single(r => r.CaseId == s.Deadline).Detail.Should().Contain("notification deadline running");

        await using var db = database.NewContext();
        var archived = await db.Cases.Where(c => c.IsArchived).Select(c => c.Id).ToListAsync();
        archived.Should().BeEquivalentTo([s.Due, s.Archived], "only the case that could be, and the one archived before");
        // A person's act, audited as theirs (ADR 0004).
        (await db.AuditLog.AnyAsync(a => a.EntityType == nameof(Case) && a.EntityId == s.Due.ToString() && a.Actor == "admin1"))
            .Should().BeTrue();
        _hasher.VerifyChain(await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();

        (await Service(database).BuildAsync()).Rows.Select(r => r.CaseId).Should().NotContain(s.Due, "archived, it leaves the review");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_batch_takes_at_most_25_cases(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);
        var many = Enumerable.Range(0, RetentionReviewService.MaxBatch).Select(_ => Guid.NewGuid()).Append(s.Due).ToList();

        RetentionReviewService.MaxBatch.Should().Be(25, "E-18's metering cap");
        await Service(database).Invoking(x => x.ArchiveAsync(many)).Should().ThrowAsync<ArgumentException>().WithMessage("*at most 25*");
        await Service(database).Invoking(x => x.ArchiveAsync([])).Should().ThrowAsync<ArgumentException>();
        await using (var db = database.NewContext())
            (await db.Cases.SingleAsync(c => c.Id == s.Due)).IsArchived.Should().BeFalse("a refused batch archives nothing");

        // 25 is allowed (here 24 unknown ids and one real one); a repeated id counts once.
        var full = many.Skip(1).Append(s.Due).ToList();
        (full.Count, full.Distinct().Count()).Should().Be((RetentionReviewService.MaxBatch + 1, RetentionReviewService.MaxBatch));
        var results = await Service(database).ArchiveAsync(full);
        results.Should().HaveCount(RetentionReviewService.MaxBatch);
        results.Single(r => r.CaseId == s.Due).Outcome.Should().Be(RetentionArchiveOutcome.Archived);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_case_reopened_during_the_batch_is_no_longer_due_and_stays_unarchived(string provider /* CAP-10 review */)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);
        var service = new RetentionReviewService(database.Factory(), _admin, _clock, CasesFor(database), _retention)
        {
            // After the batch has read which cases are due, someone reopens one.
            BeforeArchive = async id =>
            {
                if (id != s.Due) return;
                await using var other = database.NewContext();
                var c = await other.Cases.SingleAsync(x => x.Id == id);
                c.ChangePhase(CasePhase.Triage, "New activity from the same actor", "ic1", _clock.UtcNow);
                await other.SaveChangesAsync();
            },
        };

        var results = await service.ArchiveAsync([s.Due]);

        results.Should().ContainSingle().Which.Outcome.Should().Be(RetentionArchiveOutcome.NoLongerDue);
        await using var db = database.NewContext();
        var reopened = await db.Cases.SingleAsync(c => c.Id == s.Due);
        (reopened.IsArchived, reopened.Phase).Should().Be((false, CasePhase.Triage), "a reopened case isn't archived by the batch");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_case_that_fails_some_other_way_is_reported_and_the_batch_goes_on(string provider /* CAP-10 review */)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);
        var service = new RetentionReviewService(database.Factory(), _admin, _clock, CasesFor(database), _retention)
        {
            BeforeArchive = id => id == s.Restricted ? throw new DbUpdateException("The database refused the save.") : Task.CompletedTask,
        };

        var results = await service.ArchiveAsync([s.Restricted, s.Due]);

        results.Select(r => (r.CaseId, r.Outcome)).Should().Equal(
            (s.Restricted, RetentionArchiveOutcome.Failed),
            (s.Due, RetentionArchiveOutcome.Archived));
        results[0].Detail.Should().Contain("DbUpdateException");
        await using var db = database.NewContext();
        (await db.Cases.SingleAsync(c => c.Id == s.Due)).IsArchived.Should().BeTrue("the rest of the batch went ahead");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_review_lists_the_oldest_closings_up_to_its_bound_and_counts_them_all(string provider /* CAP-10 review */)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);
        await using (var db = database.NewContext())
        {
            var oldest = await db.Cases.SingleAsync(c => c.Id == s.Restricted);
            oldest.ClosedAtUtc = _clock.UtcNow.AddYears(-12);
            await db.SaveChangesAsync();
        }
        RetentionReviewService.MaxShown.Should().Be(500);
        var service = new RetentionReviewService(database.Factory(), _admin, _clock, CasesFor(database), _retention,
            new NotificationDeadlineService(database.Factory(), _deadlineSettings, new NotificationRuleService(database.Factory(), _admin, _clock), _clock))
        {
            ShowLimit = 3,
        };

        var review = await service.BuildAsync();

        review.Rows.Should().HaveCount(3);
        (review.Total, review.Cut).Should().Be((4, true), "every case due is counted, listed or not");
        review.Rows[0].CaseId.Should().Be(s.Restricted, "the oldest closing first");
        (await Service(database).BuildAsync()).Cut.Should().BeFalse("four cases are under the real bound");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_jurisdiction_already_notified_isnt_listed_as_not_recorded(string provider /* CAP-10 review */)
    {
        using var database = Open(provider);
        await SeedAsync(database);
        var old = _clock.UtcNow.AddYears(-8);
        Guid id;
        await using (var db = database.NewContext())
        {
            db.DataElements.Add(new DataElement { Key = "DL", Label = "Driver's licence number", NotificationJurisdictions = "CA",
                IsActive = true, IsSystem = false, CreatedBy = "system", CreatedAtUtc = old.AddDays(-30) });
            db.NotificationRules.Add(new NotificationRule { Code = "CA", Label = "California (CCPA)", WindowHours = 72, IsActive = true,
                CreatedBy = "system", CreatedAtUtc = old.AddDays(-30) });
            var c = Case.Open(2018, 9, "Two", "Two regulators", Classification.Breach, Severity.High, CaseOrigin.InternalDetection, "ic1",
                old.AddDays(-10));
            c.SetImpactAssessment(500, ["SSN", "DL"], "NY, CA", "ic1", old.AddDays(-9));
            c.RecordMateriality(MaterialityStatus.Material, "Disclosure Committee", old.AddDays(-8), "Likely harm.", "ic1", old.AddDays(-8));
            c.RecordNotice("NY", old.AddDays(-7), "ic1", old.AddDays(-7));
            c.ChangePhase(CasePhase.Closed, "Done", "ic1", old);
            db.Cases.Add(c);
            await db.SaveChangesAsync();
            id = c.Id;
        }

        var row = (await Service(database).BuildAsync()).Rows.Single(r => r.CaseId == id);

        row.UnreportedDeadlines.Select(d => d.Jurisdiction).Should().ContainSingle().Which.Should().Contain("California");
        row.Blocker.Should().Be("Regulatory notice not recorded");
    }

    private CaseService CasesFor(TestDatabase database) =>
        new(database.Factory(), _admin, _clock, new CaseNumberGenerator(database.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new StageGateEvaluator(), new TestSlaTargets(), notifySettings: _deadlineSettings,
            notifyRules: new NotificationRuleService(database.Factory(), _admin, _clock));

    // --- the nightly count and the monthly email -------------------------------------------------------------------

    private sealed class CapturingNotifications : ICaseNotifications
    {
        public List<RetentionReviewCount> Sent { get; } = [];
        public int FailNext { get; set; }
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnAssignedAsync(Case c, string a, string b, CaseAssignmentRole role, string by, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnRetentionReviewDueAsync(RetentionReviewCount count, CancellationToken ct = default)
        {
            Sent.Add(count);
            if (FailNext > 0) { FailNext--; DeliveryWatch.ReportFailure(); }
            return Task.CompletedTask;
        }
    }

    private RetentionReviewScanner Scanner(TestDatabase database, ICaseNotifications notifications, IRetentionReviewTracker tracker,
        RetentionReviewState? state = null) =>
        new(database.Factory(), notifications, tracker, state ?? new RetentionReviewState(), _clock);

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_nightly_count_counts_every_case_past_retention_and_changes_nothing(string provider)
    {
        using var database = Open(provider);
        await SeedAsync(database);
        var state = new RetentionReviewState();
        int entries;
        await using (var db = database.NewContext()) entries = await db.AuditLog.CountAsync();

        var count = await Scanner(database, new CapturingNotifications(), new RetentionReviewTracker(), state).CountAsync(7);

        (count.Years, count.Due, count.UnderHold).Should().Be((7, 4, 1),
            "due, held, deadline and the restricted one (a background count has no viewer); not exercises, open, recent or archived");
        state.Last.Should().Be(count, "Diagnostics shows it");
        await using (var db = database.NewContext())
        {
            (await db.AuditLog.CountAsync()).Should().Be(entries, "ADR 0004: the job only counts");
            (await db.Cases.CountAsync(c => c.IsArchived)).Should().Be(1);
        }

        var off = await Scanner(database, new CapturingNotifications(), new RetentionReviewTracker(), state).CountAsync(0);
        (off.Years, off.Due).Should().Be((0, 0));
        state.Last!.Years.Should().Be(0, "0 years is off");
        (await Scanner(database, new CapturingNotifications(), new RetentionReviewTracker()).CountAsync(20)).Due.Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_email_goes_once_a_month_only_when_on_and_something_is_due(string provider)
    {
        using var database = Open(provider);
        await SeedAsync(database);
        var notifications = new CapturingNotifications();
        var tracker = new RetentionReviewTracker();

        (await Scanner(database, notifications, tracker).ScanAsync(7, email: false)).Emailed.Should().BeFalse("the setting is off by default");
        notifications.Sent.Should().BeEmpty();

        (await Scanner(database, notifications, tracker).ScanAsync(7, email: true)).Emailed.Should().BeTrue();
        notifications.Sent.Should().ContainSingle().Which.Due.Should().Be(4);
        (await Scanner(database, notifications, tracker).ScanAsync(7, email: true)).Emailed.Should().BeFalse("once a month");

        _clock.UtcNow = _clock.UtcNow.AddMonths(1);
        (await Scanner(database, notifications, tracker).ScanAsync(7, email: true)).Emailed.Should().BeTrue("a new month");
        notifications.Sent.Should().HaveCount(2);

        (await Scanner(database, notifications, new RetentionReviewTracker()).ScanAsync(30, email: true)).Emailed
            .Should().BeFalse("nothing is due, so nothing is sent");
        notifications.Sent.Should().HaveCount(2);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_email_that_wasnt_delivered_goes_again(string provider)
    {
        using var database = Open(provider);
        await SeedAsync(database);
        var notifications = new CapturingNotifications { FailNext = 1 };
        var tracker = new RetentionReviewTracker();

        (await Scanner(database, notifications, tracker).ScanAsync(7, email: true)).Emailed.Should().BeFalse("not delivered");
        (await Scanner(database, notifications, tracker).ScanAsync(7, email: true)).Emailed.Should().BeTrue("BUG-08: tried again");
        (await Scanner(database, notifications, tracker).ScanAsync(7, email: true)).Emailed.Should().BeFalse();
        notifications.Sent.Should().HaveCount(2);
    }

    [Fact]
    public void The_email_setting_is_administered_and_off_by_default()
    {
        var email = SettingsCatalog.Editable.Single(d => d.Key == "Notifications:RetentionReview:Email");
        (email.Kind, email.Default).Should().Be((SettingKind.Bool, "false"));
        new RetentionReviewScanOptions().Email.Should().BeFalse("the bound default matches");
        SettingsCatalog.Editable.Single(d => d.Key == "Retention:CaseYears").Description.Should().Contain("0 turns the review off");
        EmailTemplateCatalog.ById("retention-review").Should().NotBeNull();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Run_now_from_Diagnostics_counts_sends_nothing_and_never_overlaps_the_nightly_count(string provider)
    {
        // CAP-29: the job is listed with its Run now when it's built; the pass only counts (ADR 0004), even with the email on.
        using var database = Open(provider);
        await SeedAsync(database);
        var notifications = new CapturingNotifications();
        var state = new RetentionReviewState();
        var services = new ServiceCollection();
        services.AddScoped(_ => Scanner(database, notifications, new RetentionReviewTracker(), state));
        await using var container = services.BuildServiceProvider();
        var jobs = new JobStatus(_clock);
        using var job = new RetentionReviewHostedService(container.GetRequiredService<IServiceScopeFactory>(), _retention,
            new TestOptionsMonitor<RetentionReviewScanOptions>(new() { Email = true }), NullLogger<RetentionReviewHostedService>.Instance, jobs);
        var audit = new ScheduledJobsTests.CapturingAudit();
        var runner = new JobRunNowService(jobs, _admin, audit, new ScheduledJobsTests.Lifetime(), NullLogger<JobRunNowService>.Instance);
        var definition = RetentionReviewHostedService.Job;
        runner.CanRunNow(definition).Should().BeTrue("listed when built, before its first pass");
        int entries;
        await using (var db = database.NewContext()) entries = await db.AuditLog.CountAsync();

        // While the nightly count holds the job, Run now is refused.
        var nightly = jobs.TryStart(definition)!;
        await FluentActions.Awaiting(() => runner.RunNowAsync(definition.Key)).Should().ThrowAsync<InvalidOperationException>();
        nightly.Dispose();

        await (await runner.RunNowAsync(definition.Key)).WaitAsync(TimeSpan.FromSeconds(30));
        var row = jobs.Snapshot().Single();
        (row.Outcome, row.Items, row.LastRunManual).Should().Be((JobOutcome.Succeeded, 4L, true));
        state.Last!.Due.Should().Be(4, "the Retention card shows the new count");
        notifications.Sent.Should().BeEmpty("Run now never sends the monthly email");
        await using (var db = database.NewContext())
            (await db.AuditLog.CountAsync()).Should().Be(entries, "nothing but the Run now's own entry (captured here) is written");
        audit.Entries.Should().ContainSingle();
    }
}
