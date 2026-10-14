using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Notifications;
using IncidentManager.Application.StageGates;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
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
/// PROD-37: the regulatory notification-deadline scanner selects open, un-reported ladder cases whose
/// deadline is at-risk or breached, reminds each case's incident commander + assignees, and — via the
/// per-band notify-once tracker — does not re-notify on a second pass. Read-only and feature-gated; it must
/// not write to the audit chain or change case state.
/// </summary>
public sealed class NotificationDeadlineScannerTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 20, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] }; // admin/config writes assert Administer (F-23)
    private readonly StubSettings _settings = new();

    public NotificationDeadlineScannerTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = NewContext();
    }

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private NotificationDeadlineService NewDeadlines() =>
        new(NewFactory(), _settings, new NotificationRuleService(NewFactory(), _user, _clock), _clock);

    private NotificationDeadlineScanner NewScanner(ICaseNotifications notifications, IDeadlineReminderTracker tracker) =>
        new(NewFactory(), NewDeadlines(), _settings, notifications, tracker);

    private sealed class CapturingNotifications : ICaseNotifications
    {
        public List<DeadlineReminder> Received { get; } = new();
        public int Calls { get; private set; }
        public int FailNext { get; set; }   // BUG-08: the next N sends fail, as the email layer reports them
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnAssignedAsync(Case c, string a, string b, CaseAssignmentRole role, string by, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnDeadlineApproachingAsync(IReadOnlyList<DeadlineReminder> reminders, CancellationToken ct = default)
        {
            Calls++;
            Received.AddRange(reminders);
            if (FailNext > 0) { FailNext--; DeliveryWatch.ReportFailure(); }
            return Task.CompletedTask;
        }
    }

    /// <summary>A material Breach whose SSN element triggers "NY" (72h rule), with the determination decided
    /// far enough in the past that the clock is already <paramref name="hoursAgo"/> into its window, plus an
    /// IC and an analyst assignee. Under the Determination basis the clock starts at the decision instant.</summary>
    private async Task<Guid> SeedMaterialBreachAsync(int hoursAgo)
    {
        await using var db = NewContext();
        db.DataElements.Add(new DataElement
        {
            Key = "SSN", Label = "Social Security number", NotificationJurisdictions = "NY",
            IsActive = true, IsSystem = false, CreatedBy = "system", CreatedAtUtc = _clock.UtcNow
        });
        // Detected before the decision (BUG-209: a decision can't precede detection).
        var c = Case.Open(2026, 1, "Breach", "Breach case", Classification.Breach, Severity.High,
            CaseOrigin.InternalDetection, "alice", _clock.UtcNow.AddHours(-hoursAgo - 1));
        c.SetImpactAssessment(500, new[] { "SSN" }, "NY", "alice", _clock.UtcNow);
        c.RecordMateriality(MaterialityStatus.Material, "Disclosure Committee", _clock.UtcNow.AddHours(-hoursAgo),
            "Reasonable likelihood of harm.", "alice", _clock.UtcNow);
        c.Assign("ic1", "IC One", CaseAssignmentRole.IncidentCommander, "alice", _clock.UtcNow);
        c.Assign("analyst1", "Analyst One", CaseAssignmentRole.Analyst, "alice", _clock.UtcNow);
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return c.Id;
    }

    private async Task SaveNyRuleAsync() =>
        await new NotificationRuleService(NewFactory(), _user, _clock)
            .SaveAsync(null, "NY", "New York (NYDFS Part 500)", 72);

    private void EnableClock() =>
        _settings.Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 72, 80);

    [Fact]
    public async Task Reminds_a_breached_case_addressing_the_ic_and_assignees()
    {
        await SeedMaterialBreachAsync(hoursAgo: 80);   // past the 72h window → Breached
        await SaveNyRuleAsync();
        EnableClock();
        var notifications = new CapturingNotifications();

        var count = await NewScanner(notifications, new DeadlineReminderTracker()).ScanAndNotifyAsync();

        count.Should().Be(1);
        var reminder = notifications.Received.Should().ContainSingle().Subject;
        reminder.State.Should().Be(SlaState.Breached);
        reminder.CaseNumber.Should().StartWith("2026-01");
        reminder.JurisdictionLabel.Should().Contain("New York");
        reminder.RecipientUserIds.Should().BeEquivalentTo(new[] { "ic1", "analyst1" });
    }

    [Fact]
    public async Task A_recipient_who_no_longer_holds_ViewCases_is_left_off(/* BUG-377 */)
    {
        await SeedMaterialBreachAsync(hoursAgo: 80);
        await SaveNyRuleAsync();
        EnableClock();
        var notifications = new CapturingNotifications();

        await new NotificationDeadlineScanner(NewFactory(), NewDeadlines(), _settings, notifications, new DeadlineReminderTracker(),
                new EntitlementUsers(("ic1", "Analyst"), ("analyst1", "")), new EntitlementRoles())
            .ScanAndNotifyAsync();

        notifications.Received.Should().ContainSingle().Which.RecipientUserIds.Should().BeEquivalentTo(new[] { "ic1" });
    }

    [Fact]
    public async Task A_breached_jurisdiction_does_not_hide_another_ones_reminders()
    {
        // BUG-191: only the headline (the soonest-due clock) was reminded, and a breached one stays the headline until
        // it's notified, so a second jurisdiction went at risk and breached unannounced.
        await SeedMaterialBreachAsync(hoursAgo: 80);
        await using (var db = NewContext())
        {
            (await db.DataElements.SingleAsync()).NotificationJurisdictions = "NY,CA";
            await db.SaveChangesAsync();
        }
        await SaveNyRuleAsync();
        await new NotificationRuleService(NewFactory(), _user, _clock).SaveAsync(null, "CA", "California", 96);
        EnableClock();
        var notifications = new CapturingNotifications();
        var tracker = new DeadlineReminderTracker();

        // 80h in: NY (72h) is past, CA (96h) is at risk (over 80%).
        (await NewScanner(notifications, tracker).ScanAndNotifyAsync()).Should().Be(2);
        notifications.Received.Select(r => (r.JurisdictionLabel, r.State)).Should().BeEquivalentTo(new[]
        {
            ("New York (NYDFS Part 500)", SlaState.Breached), ("California", SlaState.AtRisk),
        });

        // 100h in: CA is past too. NY was already reminded for its breach.
        _clock.UtcNow = _clock.UtcNow.AddHours(20);
        notifications.Received.Clear();
        (await NewScanner(notifications, tracker).ScanAndNotifyAsync()).Should().Be(1);
        notifications.Received.Single().Should().Match<DeadlineReminder>(r => r.JurisdictionLabel == "California" && r.State == SlaState.Breached);
    }

    [Fact]
    public async Task A_reminder_that_failed_to_send_is_sent_again_on_the_next_scan()
    {
        // BUG-08: the reminder used to be marked sent before delivery, so an SMTP outage lost it for good.
        await SeedMaterialBreachAsync(hoursAgo: 80);
        await SaveNyRuleAsync();
        EnableClock();
        var notifications = new CapturingNotifications { FailNext = 1 };
        var tracker = new DeadlineReminderTracker();

        (await NewScanner(notifications, tracker).ScanAndNotifyAsync()).Should().Be(0, "nothing was delivered");
        (await NewScanner(notifications, tracker).ScanAndNotifyAsync()).Should().Be(1, "the next scan tries again");
        (await NewScanner(notifications, tracker).ScanAndNotifyAsync()).Should().Be(0, "and once delivered, it isn't repeated");
        notifications.Calls.Should().Be(2);
    }

    [Fact]
    public async Task A_case_with_a_running_deadline_cant_be_archived_until_the_notice_is_recorded()
    {
        // BUG-10: archiving dropped the case from the scan and the "awaiting report" count, silencing the deadline.
        var id = await SeedMaterialBreachAsync(hoursAgo: 80);
        await SaveNyRuleAsync();
        EnableClock();
        await using var db = NewContext();
        var cases = new CaseService(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
            notifySettings: _settings, notifyRules: new NotificationRuleService(NewFactory(), _user, _clock));

        var archive = () => cases.SetArchivedAsync(id, true);
        await archive.Should().ThrowAsync<InvalidOperationException>().WithMessage("*notification deadline running*");

        await cases.MarkReportedAsync(id, _clock.UtcNow);
        await cases.SetArchivedAsync(id, true);
        (await db.Cases.AsNoTracking().SingleAsync(c => c.Id == id)).IsArchived.Should().BeTrue();
    }

    private CaseService NewCases(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
            notifySettings: _settings, notifyRules: new NotificationRuleService(NewFactory(), _user, _clock));

    [Fact]
    public async Task A_case_reported_before_any_jurisdiction_was_in_play_reopens_when_one_comes_in(/* BUG-104 */)
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 10);
        EnableClock();
        await using var db = NewContext();
        var cases = NewCases(db);
        await cases.UpdateImpactAssessmentAsync(id, 500, [], null);   // nothing in play yet
        await cases.MarkReportedAsync(id, _clock.UtcNow);
        var deadlines = NewDeadlines();
        (await deadlines.EvaluateAsync(id)).ReportedAtUtc.Should().NotBeNull();

        await cases.UpdateImpactAssessmentAsync(id, 500, ["SSN"], "NY");

        var d = await deadlines.EvaluateAsync(id);
        d.ReportedAtUtc.Should().BeNull("New York came into play after the report, so it wasn't told");
        d.Statuses.Single(s => s.JurisdictionCode == "NY").IsActive.Should().BeTrue();
    }

    private async Task SetJurisdictionsAsync(string key, string jurisdictions)
    {
        Guid elementId;
        await using (var db = NewContext()) elementId = (await db.DataElements.AsNoTracking().SingleAsync(e => e.Key == key)).Id;
        await new IncidentManager.Application.Admin.DataElementService(NewFactory(), _user, _clock)
            .SaveAsync([new IncidentManager.Application.Admin.DataElementRow(elementId, "Social Security number", jurisdictions)]);
    }

    [Fact]
    public async Task A_reported_case_keeps_the_jurisdictions_in_play_when_it_was_reported(/* WF-11 */)
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 10);
        EnableClock();
        await using var db = NewContext();
        var cases = NewCases(db);
        await cases.MarkReportedAsync(id, _clock.UtcNow);   // NY notified, so reported

        await SetJurisdictionsAsync("SSN", "NY,CA");   // an admin adds CA to the element afterwards

        var d = await NewDeadlines().EvaluateAsync(id);
        d.ReportedAtUtc.Should().NotBeNull("it was reported to every regulator in play then");
        d.Statuses.Select(s => s.JurisdictionCode).Should().Equal("NY");

        // An analyst adds another element: no notice to CA is invented under their name.
        db.DataElements.Add(new DataElement { Key = "DL", Label = "Driver's licence", NotificationJurisdictions = "NJ",
            IsActive = true, CreatedBy = "system", CreatedAtUtc = _clock.UtcNow });
        await db.SaveChangesAsync();
        await cases.UpdateImpactAssessmentAsync(id, 500, ["SSN", "DL"], "NY");
        await using var check = NewContext();
        (await check.JurisdictionNotices.AsNoTracking().Where(n => n.CaseId == id).Select(n => n.Jurisdiction).ToListAsync())
            .Should().Equal("NY");

        // BUG-284: NJ is outstanding, so the case isn't reported; what was kept still stands, so CA (added to SSN by the
        // admin later) doesn't come into play, and notifying NJ reports it again.
        var open = await NewDeadlines().EvaluateAsync(id);
        open.ReportedAtUtc.Should().BeNull();
        open.Statuses.Select(s => s.JurisdictionCode).Should().Equal("NJ", "NY");
        // BUG-287: and the NY notice still counts in the quarter it was given, though the case waits on NJ.
        await using (var q = NewContext())
        {
            var ruleSet = await new NotificationRuleService(NewFactory(), _user, _clock).LoadRuleSetAsync(_settings.Current.DefaultWindowHours);
            (await NotificationDeadlineService.NoticeOutcomesAsync(q, q.Cases.Where(c => c.Id == id), _settings.Current, ruleSet, _clock.UtcNow))
                .Should().ContainSingle().Which.State.Should().Be(SlaState.Met);
        }
        await NewCases(NewContext()).RecordNoticeAsync(id, "NJ", _clock.UtcNow);
        (await NewDeadlines().EvaluateAsync(id)).ReportedAtUtc.Should().NotBeNull();
    }

    [Fact]
    public async Task Removing_an_element_added_by_mistake_puts_the_case_back_to_reported(/* BUG-284 */)
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 10);
        EnableClock();
        await using var db = NewContext();
        var cases = NewCases(db);
        await cases.MarkReportedAsync(id, _clock.UtcNow);   // NY notified
        await SetJurisdictionsAsync("SSN", "NY,CA");        // an admin adds CA to SSN afterwards
        db.DataElements.Add(new DataElement { Key = "DL", Label = "Driver's licence", NotificationJurisdictions = "NJ",
            IsActive = true, CreatedBy = "system", CreatedAtUtc = _clock.UtcNow });
        await db.SaveChangesAsync();

        await cases.UpdateImpactAssessmentAsync(id, 500, ["SSN", "DL"], "NY");   // added by mistake: NJ comes into play
        (await NewDeadlines().EvaluateAsync(id)).ReportedAtUtc.Should().BeNull();

        await NewCases(NewContext()).UpdateImpactAssessmentAsync(id, 500, ["SSN"], "NY");   // taken out again
        var back = await NewDeadlines().EvaluateAsync(id);
        back.ReportedAtUtc.Should().NotBeNull("NY, the only regulator in play when it was reported, was notified");
        back.Statuses.Select(s => s.JurisdictionCode).Should().Equal("NY");
    }

    [Fact]
    public async Task A_notice_keeps_the_deadline_it_was_made_against(/* WF-77 */)
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 10);   // material 10 h ago: due in 62 h under 72 h
        EnableClock();
        await using var db = NewContext();
        await NewCases(db).RecordNoticeAsync(id, "NY", _clock.UtcNow);

        await using var check = NewContext();
        var due = (await check.JurisdictionNotices.AsNoTracking().SingleAsync(n => n.CaseId == id)).DueAtUtc;
        due.Should().Be(_clock.UtcNow.AddHours(62));

        // The default window shrinks later: the notice's recorded deadline doesn't move, so it stays on time.
        _settings.Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 1, 80);
        (await NewDeadlines().FreezeNoticeDuesAsync()).Should().Be(0);
        await using var after = NewContext();
        (await after.JurisdictionNotices.AsNoTracking().SingleAsync(n => n.CaseId == id)).DueAtUtc.Should().Be(due);

        // BUG-286: and the case page and the Legal register judge it the same way, against the deadline it was made under.
        var page = await NewDeadlines().EvaluateAsync(id);
        page.Statuses.Should().ContainSingle(s => s.JurisdictionCode == "NY").Which.State.Should().Be(SlaState.Met);
        var heads = await NewDeadlines().HeadlinesNowAsync(after, after.Cases.Where(c => c.Id == id), includeReported: true);
        heads[id].State.Should().Be(SlaState.Met);
    }

    [Fact]
    public async Task A_notice_given_stays_counted_when_the_trigger_is_withdrawn_later(/* BUG-375 */)
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 10);
        EnableClock();
        await using (var db = NewContext()) await NewCases(db).RecordNoticeAsync(id, "NY", _clock.UtcNow);
        var ruleSet = await new NotificationRuleService(NewFactory(), _user, _clock).LoadRuleSetAsync(_settings.Current.DefaultWindowHours);
        async Task<List<(Guid CaseId, DateTimeOffset NotifiedAtUtc, SlaState State)>> OutcomesAsync()
        {
            await using var q = NewContext();
            return await NotificationDeadlineService.NoticeOutcomesAsync(q, q.Cases.Where(c => c.Id == id), _settings.Current, ruleSet, _clock.UtcNow);
        }
        (await OutcomesAsync()).Should().ContainSingle().Which.State.Should().Be(SlaState.Met);

        // Later the materiality call is taken back and the element no longer names NY.
        await using (var db = NewContext())
        {
            var c = await db.Cases.SingleAsync(x => x.Id == id);
            c.RecordMateriality(MaterialityStatus.UnderReview, "Disclosure Committee", null, "Revisited.", "alice", _clock.UtcNow);
            (await db.DataElements.SingleAsync(e => e.Key == "SSN")).NotificationJurisdictions = "";
            await db.SaveChangesAsync();
        }
        (await NewDeadlines().EvaluateAsync(id)).AwaitingTrigger.Should().BeTrue("the live clock follows today's trigger");
        (await OutcomesAsync()).Should().ContainSingle().Which.State.Should().Be(SlaState.Met, "the notice was still given in time");
    }

    [Fact]
    public async Task Editing_a_reported_cases_count_after_an_admin_change_keeps_it_reported(/* WF-65 */)
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 10);
        EnableClock();
        await using var db = NewContext();
        var cases = NewCases(db);
        await cases.MarkReportedAsync(id, _clock.UtcNow);   // NY notified
        await SetJurisdictionsAsync("SSN", "NY,CA");        // an admin adds CA afterwards

        await cases.UpdateImpactAssessmentAsync(id, 1250, ["SSN"], "NY");   // only the count changes

        var d = await NewDeadlines().EvaluateAsync(id);
        d.ReportedAtUtc.Should().NotBeNull("the elements it had keep the jurisdictions frozen at notice time");
        d.Statuses.Select(s => s.JurisdictionCode).Should().Equal("NY");
    }

    [Fact]
    public async Task A_case_reported_before_the_upgrade_gets_its_jurisdictions_at_start_up(/* WF-11 */)
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 10);
        await using (var db = NewContext())
        {
            var c = await db.Cases.SingleAsync(x => x.Id == id);
            c.MarkReported(_clock.UtcNow, "alice", _clock.UtcNow);   // as before WF-11: nothing recorded
            await db.SaveChangesAsync();
            (await db.Cases.AsNoTracking().SingleAsync(x => x.Id == id)).ReportedJurisdictions.Should().BeNull();
        }

        long auditBefore;
        await using (var db = NewContext())
        {
            auditBefore = await db.AuditLog.LongCountAsync();
            (await IncidentManager.Infrastructure.Persistence.ReportedJurisdictionsBackfill.RunAsync(db)).Should().Be(1);
        }

        await using var check = NewContext();
        (await check.Cases.AsNoTracking().SingleAsync(x => x.Id == id)).ReportedJurisdictions.Should().Be("NY");
        // WF-93: not an audited change, which counted as a change after closure on every closed reported case.
        (await check.AuditLog.LongCountAsync()).Should().Be(auditBefore);
        (await IncidentManager.Infrastructure.Persistence.ReportedJurisdictionsBackfill.RunAsync(check)).Should().Be(0);
    }

    [Fact]
    public async Task A_legacy_notice_coded_with_a_semicolon_covers_each_code(/* BUG-428 */)
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 10);
        EnableClock();
        await SetJurisdictionsAsync("SSN", "NY,CA");
        var notifiedAt = _clock.UtcNow.AddHours(-1);
        await using (var db = NewContext())
        {
            // As recorded before BUG-404 refused separators: one notice row for "NY;CA" (hashed, so it stays as written).
            db.JurisdictionNotices.Add(new JurisdictionNotice
            {
                CaseId = id, Jurisdiction = "NY;CA", NotifiedAtUtc = notifiedAt, CreatedBy = "alice", CreatedAtUtc = notifiedAt
            });
            await db.SaveChangesAsync();
        }

        var d = await NewDeadlines().EvaluateAsync(id);
        d.Statuses.Select(s => s.JurisdictionCode).Should().BeEquivalentTo("NY", "CA");
        d.Statuses.Should().OnlyContain(s => s.NotifiedAtUtc == notifiedAt, "the notice covers both regulators");

        await using (var db = NewContext())
        {
            var c = await db.Cases.Include(x => x.JurisdictionNotices).Include(x => x.DataElements).SingleAsync(x => x.Id == id);
            c.ReportedFromNotices(["NY", "CA"], "alice", _clock.UtcNow);
            c.ReportedAtUtc.Should().Be(notifiedAt, "every jurisdiction in play was notified");
            Case.KeptJurisdictions(c.ReportedJurisdictions).Should().Equal("CA", "NY");
        }

        // The start-up backfill freezes the split codes, not "NY;CA" (whose ";" would end the codes part).
        await using (var db = NewContext())
            await db.Cases.Where(x => x.Id == id).ExecuteUpdateAsync(u => u
                .SetProperty(x => x.ReportedAtUtc, notifiedAt).SetProperty(x => x.ReportedJurisdictions, (string?)null));
        await using (var db = NewContext())
            (await IncidentManager.Infrastructure.Persistence.ReportedJurisdictionsBackfill.RunAsync(db)).Should().Be(1);
        await using var check = NewContext();
        (await check.Cases.AsNoTracking().SingleAsync(x => x.Id == id)).ReportedJurisdictions.Should().Be("CA,NY");
        (await check.JurisdictionNotices.AsNoTracking().SingleAsync()).Jurisdiction.Should().Be("NY;CA", "the hashed row isn't rewritten");
    }

    [Fact]
    public async Task A_legacy_combined_notice_keeps_its_deadline_and_outcome(/* BUG-456 */)
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 10);   // material 10 h ago
        EnableClock();                                          // 72 h default: NY due in 62 h
        await new NotificationRuleService(NewFactory(), _user, _clock).SaveAsync(null, "CA", "California", 24);   // CA due in 14 h
        await SetJurisdictionsAsync("SSN", "NY,CA");
        var notifiedAt = _clock.UtcNow.AddHours(-1);
        await using (var db = NewContext())
        {
            db.JurisdictionNotices.Add(new JurisdictionNotice
            {
                CaseId = id, Jurisdiction = "NY;CA", NotifiedAtUtc = notifiedAt, CreatedBy = "alice", CreatedAtUtc = notifiedAt
            });
            await db.SaveChangesAsync();
        }
        async Task<List<(Guid CaseId, DateTimeOffset NotifiedAtUtc, SlaState State)>> OutcomesAsync()
        {
            var ruleSet = await new NotificationRuleService(NewFactory(), _user, _clock).LoadRuleSetAsync(_settings.Current.DefaultWindowHours);
            await using var q = NewContext();
            return await NotificationDeadlineService.NoticeOutcomesAsync(q, q.Cases.Where(c => c.Id == id), _settings.Current, ruleSet, _clock.UtcNow);
        }
        (await OutcomesAsync()).Select(o => o.State).Should().Equal(SlaState.Met, SlaState.Met);   // one for each regulator

        // The start-up freeze gives the combined notice the earlier of its codes' deadlines.
        (await NewDeadlines().FreezeNoticeDuesAsync()).Should().Be(1);
        await using (var check = NewContext())
            (await check.JurisdictionNotices.AsNoTracking().SingleAsync(n => n.CaseId == id)).DueAtUtc.Should().Be(_clock.UtcNow.AddHours(14));
        (await OutcomesAsync()).Select(o => o.State).Should().Equal(SlaState.Met, SlaState.Met);   // still one each

        // The default window later shrinks to an hour: the past notice's outcome doesn't move.
        _settings.Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 1, 80);
        (await OutcomesAsync()).Select(o => o.State).Should().Equal(SlaState.Met, SlaState.Met);
        (await NewDeadlines().EvaluateAsync(id)).Statuses.Should().OnlyContain(s => s.State == SlaState.Met);
    }

    [Fact]
    public async Task Mark_reported_adds_no_second_notice_for_codes_a_legacy_notice_covers(/* BUG-428 */)
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 10);
        EnableClock();
        await SetJurisdictionsAsync("SSN", "NY,CA,TX");
        var notifiedAt = _clock.UtcNow.AddHours(-1);
        await using (var db = NewContext())
        {
            db.JurisdictionNotices.Add(new JurisdictionNotice
            {
                CaseId = id, Jurisdiction = "NY;CA", NotifiedAtUtc = notifiedAt, CreatedBy = "alice", CreatedAtUtc = notifiedAt
            });
            await db.SaveChangesAsync();
        }

        await using (var db = NewContext()) await NewCases(db).MarkReportedAsync(id, _clock.UtcNow);

        await using var check = NewContext();
        var notices = await check.JurisdictionNotices.AsNoTracking().Where(n => n.CaseId == id).ToListAsync();
        notices.Select(n => n.Jurisdiction).Should().BeEquivalentTo(["NY;CA", "TX"], "only Texas was outstanding");
        notices.Single(n => n.Jurisdiction == "NY;CA").NotifiedAtUtc.Should().Be(notifiedAt);
        var d = await NewDeadlines().EvaluateAsync(id);
        d.ReportedAtUtc.Should().Be(_clock.UtcNow);
        d.Statuses.Single(s => s.JurisdictionCode == "NY").NotifiedAtUtc.Should().Be(notifiedAt, "New York was told an hour ago");
    }

    [Fact]
    public async Task A_material_call_taken_back_and_made_again_says_when_the_clock_first_ran(/* WF-12 */)
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 10);
        EnableClock();
        var first = _clock.UtcNow.AddHours(-10);
        await using (var db = NewContext())
        {
            var c = await db.Cases.Include(x => x.MaterialityChanges).SingleAsync(x => x.Id == id);
            _clock.UtcNow = _clock.UtcNow.AddHours(1);
            c.RecordMateriality(MaterialityStatus.UnderReview, null, null, "Counsel wants another look.", "alice", _clock.UtcNow);
            await db.SaveChangesAsync();
        }
        var stopped = await NewDeadlines().EvaluateAsync(id);
        stopped.StartInstant.Should().BeNull("the clock follows the latest call");
        stopped.EarlierMaterialUtc.Should().Be(first);

        await using (var db = NewContext())
        {
            var c = await db.Cases.Include(x => x.MaterialityChanges).SingleAsync(x => x.Id == id);
            _clock.UtcNow = _clock.UtcNow.AddHours(1);
            c.RecordMateriality(MaterialityStatus.Material, "Disclosure Committee", _clock.UtcNow.AddHours(-1), "Confirmed.", "alice", _clock.UtcNow);
            await db.SaveChangesAsync();
        }
        var restarted = await NewDeadlines().EvaluateAsync(id);
        restarted.StartInstant.Should().Be(_clock.UtcNow.AddHours(-1));
        restarted.EarlierMaterialUtc.Should().Be(first);

        await using var check = NewContext();
        var full = await check.Cases.AsNoTracking().Include(x => x.MaterialityChanges).SingleAsync(x => x.Id == id);
        var notes = CaseMilestones.Project(full, new MilestoneLabels(x => "", s => "", p => p.ToString(), m => m.ToString()))
            .Where(m => m.Kind == MilestoneKind.Materiality).Select(m => m.Detail ?? "").ToList();
        notes.Should().Contain(d => d.Contains("clock stopped")).And.Contain(d => d.Contains("clock restarts"));
    }

    [Fact]
    public async Task A_case_whose_outstanding_jurisdiction_is_removed_becomes_reported(/* WF-11 */)
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 10);
        EnableClock();
        await SetJurisdictionsAsync("SSN", "NY,CA");
        await using var db = NewContext();
        var cases = NewCases(db);
        await cases.RecordNoticeAsync(id, "NY", _clock.UtcNow);
        (await NewDeadlines().EvaluateAsync(id)).ReportedAtUtc.Should().BeNull("California is outstanding");

        await SetJurisdictionsAsync("SSN", "NY");   // an admin takes CA off the element

        (await NewDeadlines().EvaluateAsync(id)).ReportedAtUtc.Should().Be(_clock.UtcNow, "every jurisdiction in play is notified");
    }

    [Fact]
    public async Task Re_scoping_to_nothing_in_play_keeps_the_notices_made(/* BUG-104 */)
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 10);
        EnableClock();
        await using var db = NewContext();
        var cases = NewCases(db);
        await cases.RecordNoticeAsync(id, "NY", _clock.UtcNow);
        (await NewDeadlines().EvaluateAsync(id)).ReportedAtUtc.Should().Be(_clock.UtcNow);

        await cases.UpdateImpactAssessmentAsync(id, 500, [], null);

        (await NewDeadlines().EvaluateAsync(id)).ReportedAtUtc.Should().Be(_clock.UtcNow, "the regulator was still notified");
    }

    [Fact]
    public async Task Each_regulator_is_notified_on_its_own_and_the_case_is_reported_when_all_are()
    {
        // BUG-09: one case-level reported time used to mark every jurisdiction met.
        var id = await SeedMaterialBreachAsync(hoursAgo: 60);
        await SaveNyRuleAsync();
        EnableClock();
        await using var db = NewContext();
        db.DataElements.Add(new DataElement
        {
            Key = "DL", Label = "Driver's licence", NotificationJurisdictions = "CA",
            IsActive = true, IsSystem = false, CreatedBy = "system", CreatedAtUtc = _clock.UtcNow
        });
        await db.SaveChangesAsync();
        var cases = NewCases(db);
        await cases.UpdateImpactAssessmentAsync(id, 500, ["SSN", "DL"], "NY,CA");
        var deadlines = NewDeadlines();

        await cases.RecordNoticeAsync(id, "ny", _clock.UtcNow);
        var d = await deadlines.EvaluateAsync(id);
        d.Statuses.Single(s => s.JurisdictionCode == "NY").State.Should().Be(SlaState.Met);
        d.Statuses.Single(s => s.JurisdictionCode == "CA").IsActive.Should().BeTrue("California hasn't been told");
        d.ReportedAtUtc.Should().BeNull("the case is reported once every regulator in play is");
        (await NewScanner(new CapturingNotifications(), new DeadlineReminderTracker()).ScanAndNotifyAsync())
            .Should().Be(1, "California's reminder still goes out");

        _clock.UtcNow = _clock.UtcNow.AddHours(1);
        await cases.RecordNoticeAsync(id, "CA", _clock.UtcNow);
        (await deadlines.EvaluateAsync(id)).ReportedAtUtc.Should().Be(_clock.UtcNow, "the last notice completes it");

        // A data element that brings a new jurisdiction into play reopens it.
        db.DataElements.Add(new DataElement
        {
            Key = "MED", Label = "Medical record", NotificationJurisdictions = "TX",
            IsActive = true, IsSystem = false, CreatedBy = "system", CreatedAtUtc = _clock.UtcNow
        });
        await db.SaveChangesAsync();
        await cases.UpdateImpactAssessmentAsync(id, 500, ["SSN", "DL", "MED"], "NY,CA,TX");
        (await deadlines.EvaluateAsync(id)).ReportedAtUtc.Should().BeNull();

        // Recording "all at once" covers only the regulators not yet notified.
        await cases.MarkReportedAsync(id, _clock.UtcNow);
        var all = await deadlines.EvaluateAsync(id);
        all.ReportedAtUtc.Should().NotBeNull();
        all.NoticeCodes.Should().BeEquivalentTo(["NY", "CA", "TX"]);
        all.Statuses.Single(s => s.JurisdictionCode == "NY").NotifiedAtUtc.Should().BeBefore(_clock.UtcNow, "NY's earlier notice stands");
    }

    [Fact]
    public async Task A_case_reported_before_per_jurisdiction_notices_keeps_its_meaning()
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 60);
        await SaveNyRuleAsync();
        EnableClock();
        await using (var db = NewContext())
        {
            var c = await db.Cases.SingleAsync(x => x.Id == id);
            c.ReportedAtUtc = _clock.UtcNow;   // as written before notices were per jurisdiction
            await db.SaveChangesAsync();
        }
        var d = await NewDeadlines().EvaluateAsync(id);
        d.Statuses.Should().OnlyContain(s => s.State == SlaState.Met);
        d.NoticeCodes.Should().BeEmpty();
    }

    [Fact]
    public async Task Reminds_an_at_risk_case()
    {
        await SeedMaterialBreachAsync(hoursAgo: 60);   // 60h of 72h, past the 80% (57.6h) mark → AtRisk
        await SaveNyRuleAsync();
        EnableClock();
        var notifications = new CapturingNotifications();

        (await NewScanner(notifications, new DeadlineReminderTracker()).ScanAndNotifyAsync()).Should().Be(1);
        notifications.Received.Single().State.Should().Be(SlaState.AtRisk);
    }

    [Fact]
    public async Task Does_not_remind_an_on_track_case()
    {
        await SeedMaterialBreachAsync(hoursAgo: 1);     // just decided → well inside the window
        await SaveNyRuleAsync();
        EnableClock();
        var notifications = new CapturingNotifications();

        (await NewScanner(notifications, new DeadlineReminderTracker()).ScanAndNotifyAsync()).Should().Be(0);
        notifications.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Does_nothing_when_the_feature_is_off()
    {
        await SeedMaterialBreachAsync(hoursAgo: 80);
        await SaveNyRuleAsync();
        _settings.Current = NotificationDeadlineSettings.Off;
        var notifications = new CapturingNotifications();

        (await NewScanner(notifications, new DeadlineReminderTracker()).ScanAndNotifyAsync()).Should().Be(0);
        notifications.Calls.Should().Be(0);
    }

    [Fact]
    public async Task A_second_pass_in_the_same_band_does_not_re_notify()
    {
        await SeedMaterialBreachAsync(hoursAgo: 80);
        await SaveNyRuleAsync();
        EnableClock();
        var notifications = new CapturingNotifications();
        var tracker = new DeadlineReminderTracker();          // shared across passes, like the DI singleton
        var scanner = NewScanner(notifications, tracker);

        (await scanner.ScanAndNotifyAsync()).Should().Be(1);
        (await scanner.ScanAndNotifyAsync()).Should().Be(0);  // already reminded for the Breached band
        notifications.Calls.Should().Be(1);
    }

    [Fact]
    public async Task A_reported_case_is_not_reminded()
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 80);
        await SaveNyRuleAsync();
        EnableClock();
        await using (var db = NewContext())
        {
            var c = await db.Cases.FirstAsync(x => x.Id == id);
            c.MarkReported(_clock.UtcNow, "alice", _clock.UtcNow);
            await db.SaveChangesAsync();
        }
        var notifications = new CapturingNotifications();

        (await NewScanner(notifications, new DeadlineReminderTracker()).ScanAndNotifyAsync()).Should().Be(0);
    }

    [Fact]
    public async Task A_closed_case_with_an_unrecorded_notification_is_still_reminded()
    {
        // INV-43: closing doesn't answer the notification, so the watch continues.
        var id = await SeedMaterialBreachAsync(hoursAgo: 80);
        await SaveNyRuleAsync();
        EnableClock();
        await using (var db = NewContext())
        {
            var c = await db.Cases.FirstAsync(x => x.Id == id);
            c.ChangePhase(CasePhase.Closed, "Done", "alice", _clock.UtcNow);
            await db.SaveChangesAsync();
        }
        var notifications = new CapturingNotifications();

        (await NewScanner(notifications, new DeadlineReminderTracker()).ScanAndNotifyAsync()).Should().Be(1);
    }

    [Fact]
    public async Task The_close_gate_check_fails_while_the_notification_is_unrecorded()
    {
        // INV-43: the NotificationsRecorded fact mirrors the countdown: a running clock with no report time.
        var id = await SeedMaterialBreachAsync(hoursAgo: 10);
        await using (var db = NewContext())
        {
            db.StageGates.Add(new StageGate
            {
                Trigger = StageGateTrigger.CloseCase, Name = "Closure", IsActive = true,
                CreatedBy = "system", CreatedAtUtc = _clock.UtcNow,
                Requirements =
                {
                    new StageGateRequirement
                    {
                        Kind = GateRequirementKind.MachineCheck, CheckKey = GateCheckKeys.NotificationsRecorded,
                        Label = "Required regulatory notifications recorded", IsBlocking = true, Order = 1
                    }
                }
            });
            await db.SaveChangesAsync();
        }
        EnableClock();
        var evaluator = new StageGateEvaluator(_settings);

        async Task<bool> Passes()
        {
            await using var db = NewContext();
            var eval = await evaluator.EvaluateAsync(db, id, StageGateTrigger.CloseCase);
            return eval.Requirements.Single().MachineSatisfied;
        }

        (await Passes()).Should().BeFalse();

        await using (var db = NewContext())
        {
            var c = await db.Cases.FirstAsync(x => x.Id == id);
            c.MarkReported(_clock.UtcNow, "alice", _clock.UtcNow);
            await db.SaveChangesAsync();
        }
        (await Passes()).Should().BeTrue();

        _settings.Current = NotificationDeadlineSettings.Off;   // feature off: no clock, nothing pending
        (await new StageGateEvaluator().EvaluateAsync(NewContext(), id, StageGateTrigger.CloseCase))
            .Requirements.Single().MachineSatisfied.Should().BeTrue();
    }

    private sealed class StubSettings : INotificationDeadlineSettingsProvider
    {
        public NotificationDeadlineSettings Current { get; set; } = NotificationDeadlineSettings.Off;
    }

    public void Dispose() => _connection.Dispose();
}
