using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Notifications;
using IncidentManager.Application.Reporting;
using IncidentManager.Application.Security;
using IncidentManager.Application.Sla;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Reporting;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-38: each jurisdiction's notification clock stops only at a notice recorded for it (a notice to NY never stops CA's),
/// and the case counts as reported only when every jurisdiction in play has one; until then it's partly reported. The case
/// page and Briefing, the report, the close gate, the reminder scan and the legal register all read that through one
/// function (<see cref="NoticeStanding"/>), so they agree. A case reported as a whole before notices were per jurisdiction
/// keeps counting every jurisdiction then in play as notified at its reported time, without notice rows invented for it.
/// Runs on SQLite always and on SQL Server when <c>CASEBOOK_TEST_SQL</c> is set.
/// </summary>
public sealed class PerJurisdictionClockTests : IDisposable
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "ic1", RoleSet = [AppRole.SysAdmin] };
    private readonly StubSettings _settings = new()
    {
        Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 72, 80),
    };
    private readonly CapturingSecurityEventSink _siem = new();
    private readonly DeadlineReminderTracker _tracker = new();
    private readonly string _reportDir = Path.Combine(Path.GetTempPath(), "im-cap38-tests", Guid.NewGuid().ToString("N"));
    private int _next;

    public static TheoryData<string> Providers => TestDatabase.Providers;

    // The clock started 60 h ago (Material call); the 72 h default window is due in 12 h, so every clock is at risk.
    private DateTimeOffset Start => new(2026, 10, 16, 0, 0, 0, TimeSpan.Zero);
    private DateTimeOffset Due => Start.AddHours(72);

    private TestDatabase Open(string provider)
    {
        var database = TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
        using var db = database.NewContext();
        foreach (var (key, label, juris) in new[]
                 {
                     ("SSN", "Social Security number", "NY"), ("DL", "Driver's licence", "CA"),
                     ("PASS", "Passport number", "TX"), ("EMAIL", "Email address", ""),
                 })
            db.DataElements.Add(new DataElement
            {
                Key = key, Label = label, NotificationJurisdictions = juris, IsActive = true,
                CreatedBy = "system", CreatedAtUtc = _clock.UtcNow,
            });
        db.StageGates.Add(new StageGate
        {
            Trigger = StageGateTrigger.CloseCase, Name = "Closure", IsActive = true, CreatedBy = "system", CreatedAtUtc = _clock.UtcNow,
            Requirements =
            {
                new StageGateRequirement
                {
                    Kind = GateRequirementKind.MachineCheck, CheckKey = GateCheckKeys.NotificationsRecorded,
                    Label = "Required regulatory notifications recorded", IsBlocking = true, Order = 1,
                },
            },
        });
        db.SaveChanges();
        return database;
    }

    private NotificationRuleService Rules(TestDatabase database) => new(database.Factory(), _user, _clock);

    private NotificationDeadlineService Deadlines(TestDatabase database) => new(database.Factory(), _settings, Rules(database), _clock);

    private CaseService Cases(TestDatabase database) =>
        new(database.Factory(), _user, _clock, new CaseNumberGenerator(database.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new StageGateEvaluator(_settings), new TestSlaTargets(), siem: _siem,
            notifySettings: _settings, notifyRules: Rules(database), deadlineReminders: _tracker);

    private ReportService Reports(TestDatabase database) =>
        new(database.Factory(), new ReportGenerator(),
            new FileReportStore(Options.Create(new ReportOutputOptions { RootPath = _reportDir })), _hasher, _user, _clock,
            new IncidentManager.Application.Content.MarkdownService(), new TestOptionsMonitor<ReportingOptions>(new ReportingOptions()),
            new FileReportBrandingStore(Options.Create(new ReportBrandingOptions { RootPath = Path.Combine(_reportDir, "branding") })),
            new ListedUserDirectory(),
            new IncidentManager.Infrastructure.Severities.ConfigurationSeverityLabels(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()),
            deadlines: Deadlines(database));

    // A material Breach whose clock started at Start, with the elements given (SSN: NY, DL: CA, PASS: TX, EMAIL: none).
    private async Task<Guid> SeedAsync(TestDatabase database, params string[] elements)
    {
        await using var db = database.NewContext();
        var n = ++_next;
        var c = Case.Open(2026, n, $"Clock{n}", $"Clock case {n}", Classification.Breach, Severity.High,
            CaseOrigin.InternalDetection, "alice", Start.AddHours(-1));
        c.SetImpactAssessment(500, elements, null, "alice", _clock.UtcNow);
        c.RecordMateriality(MaterialityStatus.Material, "Disclosure Committee", Start, "Reasonable likelihood of harm.", "alice", _clock.UtcNow);
        c.Assign("ic1", "IC One", CaseAssignmentRole.IncidentCommander, "alice", _clock.UtcNow);
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return c.Id;
    }

    // As a case reported before notices were recorded per jurisdiction left it: one reported time, no notice rows. With
    // keptInPlay, what was in play then was recorded (WF-11); without, it's back-filled from today's settings.
    private async Task LegacyReportAsync(TestDatabase database, Guid id, DateTimeOffset at, IReadOnlyCollection<string>? keptInPlay)
    {
        await using var db = database.NewContext();
        var c = await db.Cases.Include(x => x.DataElements).SingleAsync(x => x.Id == id);
        c.MarkReported(at, "legacy", at, keptInPlay);
        await db.SaveChangesAsync();
    }

    private sealed class CapturingNotifications : ICaseNotifications
    {
        public List<DeadlineReminder> Received { get; } = [];
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnAssignedAsync(Case c, string a, string b, CaseAssignmentRole role, string by, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnDeadlineApproachingAsync(IReadOnlyList<DeadlineReminder> reminders, CancellationToken ct = default)
        {
            Received.AddRange(reminders);
            return Task.CompletedTask;
        }
    }

    // The jurisdictions the reminder scan reminds about now, per case (with the given tracker: the test's own by default).
    private async Task<Dictionary<Guid, List<string>>> ScanAsync(TestDatabase database, IDeadlineReminderTracker? tracker = null)
    {
        var sent = new CapturingNotifications();
        await new NotificationDeadlineScanner(database.Factory(), Deadlines(database), _settings, sent, tracker ?? _tracker).ScanAndNotifyAsync();
        return sent.Received.GroupBy(r => r.CaseId)
            .ToDictionary(g => g.Key, g => g.SelectMany(r => r.JurisdictionCodes).Order(StringComparer.Ordinal).ToList());
    }

    private async Task<bool> GateMetAsync(TestDatabase database, Guid id)
    {
        await using var db = database.NewContext();
        return (await new StageGateEvaluator(_settings).EvaluateAsync(db, id, StageGateTrigger.CloseCase)).Requirements.Single().MachineSatisfied;
    }

    private async Task<Case> LoadAsync(TestDatabase database, Guid id)
    {
        await using var db = database.NewContext();
        return await db.Cases.AsNoTracking().AsSplitQuery().Include(x => x.JurisdictionNotices).Include(x => x.Evidence)
            .SingleAsync(x => x.Id == id);
    }

    private static string Utc(DateTimeOffset t) => $"{t.UtcDateTime:yyyy-MM-dd HH:mm} UTC";

    private static List<string> Running(CaseNotificationDeadlines d) =>
        d.Statuses.Where(s => s.IsActive).Select(s => s.JurisdictionCode).Order(StringComparer.Ordinal).ToList();

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_notice_to_NY_leaves_CAs_clock_running_and_the_case_partly_reported(string provider)
    {
        using var database = Open(provider);
        var svc = Cases(database);
        var id = await SeedAsync(database, "SSN", "DL");
        (await ScanAsync(database))[id].Should().Equal("CA", "NY");
        var ny = _clock.UtcNow.AddHours(-2);

        await svc.RecordNoticeAsync(id, "NY", ny);

        var d = await Deadlines(database).EvaluateAsync(id);
        d.Statuses.Single(s => s.JurisdictionCode == "NY").Should().Match<NotificationDeadlineStatus>(s => s.State == SlaState.Met && s.NotifiedAtUtc == ny);
        Running(d).Should().Equal(["CA"], "a notice to NY never stops CA's clock");
        d.Standing.IsPartlyReported.Should().BeTrue();
        d.Standing.IsFullyReported.Should().BeFalse();
        (await LoadAsync(database, id)).ReportedAtUtc.Should().BeNull("the case isn't reported while CA is owed");

        var model = await Reports(database).BuildPreviewModelAsync(id, null);
        model.ReportedAtUtc.Should().BeNull();
        model.NotificationStanding.Should().Be($"Partly reported: NY notified {Utc(ny)}, CA due {Utc(Due)}.");
        model.BusinessImpactLines.Should().Contain(model.NotificationStanding);
        model.OutcomeStamps.Should().NotContain(s => s.StartsWith("Reported to regulators", StringComparison.Ordinal));
        ReportTemplateFields.Scalar(model, "case.notification_standing").Should().Be(model.NotificationStanding);
        NoticeDetailText.Standing(d, Utc).Should().Be(model.NotificationStanding, "the Briefing says it in the same words");
        (await GateMetAsync(database, id)).Should().BeFalse("CA's notice isn't recorded");

        var milestones = CaseMilestones.Project(await LoadAsync(database, id), new MilestoneLabels(x => "", s => "", p => "", m => ""));
        milestones.Should().Contain(m => m.Title == "Notified NY").And.NotContain(m => m.Kind == MilestoneKind.Reported && m.Title.StartsWith("Reported"));

        // Past the deadline, CA is reminded again (breached); NY, notified, isn't.
        _clock.UtcNow = Due.AddHours(1);
        (await ScanAsync(database))[id].Should().Equal("CA");

        _siem.Events.Where(e => e.EventId == SecurityEventIds.CaseReported).Select(e => (e.Action, e.Detail))
            .Should().Equal([("RegulatorNoticeRecorded", "jurisdiction=NY")], "partly reported sends only the regulator's own event");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task With_both_notified_the_case_is_fully_reported_and_the_gate_is_met(string provider)
    {
        using var database = Open(provider);
        var svc = Cases(database);
        var id = await SeedAsync(database, "SSN", "DL");
        var (ny, ca) = (_clock.UtcNow.AddHours(-2), _clock.UtcNow.AddHours(-1));
        await svc.RecordNoticeAsync(id, "NY", ny);
        await svc.RecordNoticeAsync(id, "CA", ca);

        var d = await Deadlines(database).EvaluateAsync(id);
        Running(d).Should().BeEmpty();
        d.Standing.IsFullyReported.Should().BeTrue();
        (await LoadAsync(database, id)).ReportedAtUtc.Should().Be(ca, "the case is reported when the last regulator in play was");
        (await GateMetAsync(database, id)).Should().BeTrue();
        (await ScanAsync(database)).Should().NotContainKey(id);
        var model = await Reports(database).BuildPreviewModelAsync(id, null);
        model.ReportedAtUtc.Should().Be(ca);
        model.NotificationStanding.Should().Be($"Reported to every regulator in play: CA notified {Utc(ca)}, NY notified {Utc(ny)}.");

        _siem.Events.Where(e => e.EventId == SecurityEventIds.CaseReported).Select(e => (e.Action, e.Detail)).Should().Equal(
            ("RegulatorNoticeRecorded", "jurisdiction=NY"), ("RegulatorNoticeRecorded", "jurisdiction=CA"), ("CaseReported", null));
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_jurisdiction_brought_in_after_the_full_report_puts_the_case_back_to_partly_reported(string provider)
    {
        using var database = Open(provider);
        var svc = Cases(database);
        var id = await SeedAsync(database, "SSN", "DL");
        var (ny, ca) = (_clock.UtcNow.AddHours(-2), _clock.UtcNow.AddHours(-1));
        await svc.RecordNoticeAsync(id, "NY", ny);
        await svc.RecordNoticeAsync(id, "CA", ca);

        await svc.UpdateImpactAssessmentAsync(id, 500, ["SSN", "DL", "PASS"], null);   // PASS brings TX in

        var d = await Deadlines(database).EvaluateAsync(id);
        Running(d).Should().Equal(["TX"]);
        d.Standing.IsPartlyReported.Should().BeTrue();
        (await LoadAsync(database, id)).ReportedAtUtc.Should().BeNull();
        (await GateMetAsync(database, id)).Should().BeFalse();
        (await ScanAsync(database))[id].Should().Equal("TX");
        (await Reports(database).BuildPreviewModelAsync(id, null)).NotificationStanding
            .Should().Be($"Partly reported: CA notified {Utc(ca)}, NY notified {Utc(ny)}, TX due {Utc(Due)}.");

        // BUG-555: a case reported as a whole with nothing in play runs the clock an element added brings in.
        var whole = await SeedAsync(database, "EMAIL");
        await svc.MarkReportedAsync(whole, _clock.UtcNow.AddHours(-3));
        (await Deadlines(database).EvaluateAsync(whole)).Standing.IsFullyReported.Should().BeTrue();
        await svc.UpdateImpactAssessmentAsync(whole, 500, ["EMAIL", "SSN"], null);
        var w = await Deadlines(database).EvaluateAsync(whole);
        Running(w).Should().Equal(["NY"]);
        w.Standing.IsFullyReported.Should().BeFalse();
        (await GateMetAsync(database, whole)).Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Removing_a_notice_runs_that_clock_again(string provider)
    {
        using var database = Open(provider);
        var svc = Cases(database);
        var id = await SeedAsync(database, "SSN", "DL");
        await svc.RecordNoticeAsync(id, "NY", _clock.UtcNow.AddHours(-2));
        (await ScanAsync(database))[id].Should().Equal("CA");
        await svc.RecordNoticeAsync(id, "CA", _clock.UtcNow.AddHours(-1));

        await svc.RemoveNoticeAsync(id, "CA");

        var d = await Deadlines(database).EvaluateAsync(id);
        Running(d).Should().Equal(["CA"]);
        d.Statuses.Single(s => s.JurisdictionCode == "NY").State.Should().Be(SlaState.Met, "NY's own notice still stops NY's clock");
        d.Standing.IsPartlyReported.Should().BeTrue();
        (await GateMetAsync(database, id)).Should().BeFalse();
        (await ScanAsync(database))[id].Should().Equal(["CA"], "BUG-619: CA is reminded again; NY isn't");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_case_reported_as_a_whole_before_per_jurisdiction_notices_shows_no_overdue_clock_and_sends_no_reminder(string provider)
    {
        using var database = Open(provider);
        var kept = await SeedAsync(database, "SSN", "DL");
        var backFilled = await SeedAsync(database, "SSN", "DL");
        var at = Start.AddHours(50);   // inside the window
        await LegacyReportAsync(database, kept, at, ["NY", "CA"]);
        await LegacyReportAsync(database, backFilled, at, null);
        _clock.UtcNow = Due.AddHours(30);   // well past every deadline

        foreach (var id in new[] { kept, backFilled })
        {
            var d = await Deadlines(database).EvaluateAsync(id);
            d.Statuses.Should().HaveCount(2).And.AllSatisfy(s =>
                s.Should().Match<NotificationDeadlineStatus>(x => x.State == SlaState.Met && x.NotifiedAtUtc == at));
            d.Standing.IsFullyReported.Should().BeTrue();
            (await GateMetAsync(database, id)).Should().BeTrue();
            (await Reports(database).BuildPreviewModelAsync(id, null)).NotificationStanding
                .Should().Be($"Reported to every regulator in play: CA notified {Utc(at)}, NY notified {Utc(at)}.");
        }
        (await ScanAsync(database)).Should().BeEmpty("a legacy reported time counts for every jurisdiction then in play");

        // Read, not rewritten: no notice row is invented, and the chain still verifies.
        await using var db = database.NewContext();
        (await db.JurisdictionNotices.CountAsync()).Should().Be(0);
        _hasher.VerifyChain(await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Mark_reported_records_a_notice_for_each_regulator_still_owed_so_each_clock_has_its_own_stop(string provider)
    {
        using var database = Open(provider);
        var svc = Cases(database);
        var id = await SeedAsync(database, "SSN", "DL");
        var ny = _clock.UtcNow.AddHours(-3);
        await svc.RecordNoticeAsync(id, "NY", ny);
        var rest = _clock.UtcNow.AddHours(-1);

        await svc.MarkReportedAsync(id, rest, Shown.Of<DateTimeOffset?>(null));

        var c = await LoadAsync(database, id);
        c.JurisdictionNotices.ToDictionary(n => n.Jurisdiction, n => n.NotifiedAtUtc)
            .Should().Equal(new Dictionary<string, DateTimeOffset> { ["NY"] = ny, ["CA"] = rest }, "NY keeps its own time");
        c.ReportedAtUtc.Should().Be(rest);
        (await Deadlines(database).EvaluateAsync(id)).Standing.IsFullyReported.Should().BeTrue();
        (await GateMetAsync(database, id)).Should().BeTrue();
        _siem.Events.Where(e => e.EventId == SecurityEventIds.CaseReported).Select(e => (e.Action, e.Detail)).Should().Equal(
            ("RegulatorNoticeRecorded", "jurisdiction=NY"), ("RegulatorNoticeRecorded", "jurisdiction=CA"), ("CaseReported", null));

        // With nothing in play, it records the case's reported time alone: there's no clock it could contradict.
        var none = await SeedAsync(database, "EMAIL");
        await svc.MarkReportedAsync(none, rest);
        var n = await LoadAsync(database, none);
        (n.ReportedAtUtc, n.JurisdictionNotices.Count).Should().Be((rest, 0));
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_stored_reported_time_over_a_running_clock_doesnt_silence_it(string provider)
    {
        // A reported time set while CA is still owed (written around CaseService, as an older build or a DBA could): every
        // view goes by the notices, not the stored time, so CA's clock still runs, is reminded and holds the gate.
        using var database = Open(provider);
        var id = await SeedAsync(database, "SSN", "DL");
        await Cases(database).RecordNoticeAsync(id, "NY", _clock.UtcNow.AddHours(-2));
        await LegacyReportAsync(database, id, _clock.UtcNow.AddHours(-1), null);
        (await LoadAsync(database, id)).ReportedAtUtc.Should().NotBeNull();

        var d = await Deadlines(database).EvaluateAsync(id);
        Running(d).Should().Equal(["CA"]);
        d.Standing.IsPartlyReported.Should().BeTrue();
        (await ScanAsync(database))[id].Should().Equal("CA");
        (await GateMetAsync(database, id)).Should().BeFalse();
        (await Reports(database).BuildPreviewModelAsync(id, null)).NotificationStanding.Should().StartWith("Partly reported: NY notified");
        (await new LegalRegisterService(database.Factory(), _user, Deadlines(database), new ListedUserDirectory()).BuildAsync())
            .Single().Should().Match<LegalRegisterRow>(r => r.ReportedAtUtc == null && r.PartlyReported);
        await using var db = database.NewContext();
        (await NotificationDeadlineService.OpenHeadlinesAsync(db, db.Cases.AsNoTracking(), _settings.Current,
            await Rules(database).LoadRuleSetAsync(72), _clock.UtcNow)).Should().ContainKey(id, "the dashboard counts it as awaiting report");

        // CAP-38 review: nor does the report, the timeline, the narrative or the case-list CSV say "reported" beside it.
        var model = await Reports(database).BuildPreviewModelAsync(id, null);
        model.ReportedAtUtc.Should().BeNull("the report's reported time is the standing's, not the stored one");
        model.OutcomeStamps.Should().NotContain(s => s.StartsWith("Reported to regulators", StringComparison.Ordinal));
        ReportTemplateFields.Scalar(model, "case.reported").Should().BeEmpty();
        model.InvestigationTimeline.Should().NotContain(t => t.Description.StartsWith("Reported to", StringComparison.Ordinal));
        var full = await LoadAsync(database, id);
        var milestones = CaseMilestones.Project(full, new MilestoneLabels(x => "", s => "", p => "", m => "", Standing: d.Standing));
        milestones.Should().Contain(m => m.Title == "Notified NY").And.NotContain(m => m.Key.StartsWith("reported:", StringComparison.Ordinal), "no reported milestone");
        IncidentManager.Application.Lessons.CaseNarrative.Draft(full, _ => null, s => s.ToString(), _clock.UtcNow, d.Standing)
            .Should().NotContain("Reported to regulators");
        (await CaseListCsv.CollectAsync(Cases(database), new CaseFilter())).Items.Single(i => i.Id == id).ReportedAtUtc.Should().BeNull();
    }

    // --- CAP-38 review: Mark reported records only the regulators the form showed as owed ---

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Mark_reported_is_refused_when_a_regulator_came_into_play_after_the_form_showed_who_is_owed(string provider)
    {
        using var database = Open(provider);
        var svc = Cases(database);
        var id = await SeedAsync(database, "SSN", "DL");
        await svc.RecordNoticeAsync(id, "NY", _clock.UtcNow.AddHours(-3));
        var shown = (await Deadlines(database).EvaluateAsync(id)).Standing.Outstanding;
        shown.Should().Equal(["CA"]);

        await Cases(database).UpdateImpactAssessmentAsync(id, 500, ["SSN", "DL", "PASS"], null);   // a colleague: PASS brings TX in

        var at = _clock.UtcNow.AddHours(-1);
        await svc.Invoking(s => s.MarkReportedAsync(id, at, Shown.Of<DateTimeOffset?>(null), shown))
            .Should().ThrowAsync<StaleEditException>().WithMessage("*now CA, TX*");
        (await LoadAsync(database, id)).JurisdictionNotices.Select(n => n.Jurisdiction).Should().Equal(["NY"], "no notice to TX (or CA) that nobody saw");

        // Having looked again (the page reloads the set), the save records both, in any order and case.
        await svc.MarkReportedAsync(id, at, Shown.Of<DateTimeOffset?>(null), ["tx", "CA"]);
        (await LoadAsync(database, id)).JurisdictionNotices.Select(n => n.Jurisdiction).Order(StringComparer.Ordinal).Should().Equal(["CA", "NY", "TX"]);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Mark_reported_is_refused_when_a_notice_was_removed_after_the_form_opened(string provider)
    {
        using var database = Open(provider);
        var svc = Cases(database);
        var id = await SeedAsync(database, "SSN", "DL", "PASS");
        await svc.RecordNoticeAsync(id, "NY", _clock.UtcNow.AddHours(-3));
        await svc.RecordNoticeAsync(id, "CA", _clock.UtcNow.AddHours(-3));
        var shown = (await Deadlines(database).EvaluateAsync(id)).Standing.Outstanding;
        shown.Should().Equal(["TX"]);

        await Cases(database).RemoveNoticeAsync(id, "CA");   // a colleague takes back CA's notice (a mis-entry)

        await svc.Invoking(s => s.MarkReportedAsync(id, _clock.UtcNow.AddHours(-1), Shown.Of<DateTimeOffset?>(null), shown))
            .Should().ThrowAsync<StaleEditException>();
        (await LoadAsync(database, id)).JurisdictionNotices.Select(n => n.Jurisdiction).Should().Equal(["NY"], "CA's notice isn't made again");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_case_reported_event_is_sent_once_whichever_path_leaves_the_case_fully_reported(string provider)
    {
        using var database = Open(provider);
        var svc = Cases(database);
        IEnumerable<(string Action, string? Detail)> Reported() =>
            _siem.Events.Where(e => e.EventId == SecurityEventIds.CaseReported).Select(e => (e.Action, e.Detail));

        // Removing the element that brought in the one regulator still owed.
        var removed = await SeedAsync(database, "SSN", "DL", "PASS");
        await svc.RecordNoticeAsync(removed, "NY", _clock.UtcNow.AddHours(-2));
        await svc.RecordNoticeAsync(removed, "CA", _clock.UtcNow.AddHours(-2));
        _siem.Events.Clear();
        await svc.UpdateImpactAssessmentAsync(removed, 500, ["SSN", "DL"], null);
        (await Deadlines(database).EvaluateAsync(removed)).Standing.IsFullyReported.Should().BeTrue();
        Reported().Should().Equal([("CaseReported", (string?)null)]);

        // A data element's jurisdictions changed (the recheck): DL brings in no regulator any more.
        var rechecked = await SeedAsync(database, "SSN", "DL");
        await svc.RecordNoticeAsync(rechecked, "NY", _clock.UtcNow.AddHours(-2));
        _siem.Events.Clear();
        DataElement dl;
        await using (var db = database.NewContext()) dl = await db.DataElements.AsNoTracking().SingleAsync(e => e.Key == "DL");
        var rows = new List<DataElementRow>();
        await using (var db = database.NewContext())
            rows.AddRange((await db.DataElements.AsNoTracking().Where(e => e.IsActive).OrderBy(e => e.SortOrder).ToListAsync())
                .Select(e => new DataElementRow(e.Id, e.Label, e.Id == dl.Id ? "" : e.NotificationJurisdictions)));
        await new DataElementService(database.Factory(), _user, _clock, _siem).SaveAsync(rows);
        (await LoadAsync(database, rechecked)).ReportedAtUtc.Should().NotBeNull();
        Reported().Should().Equal([("CaseReported", (string?)null)]);

        // Mark reported with every regulator already notified records nothing, and says nothing.
        _siem.Events.Clear();
        await svc.MarkReportedAsync(removed, _clock.UtcNow);
        Reported().Should().BeEmpty("nothing was recorded");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_kept_value_too_long_for_its_elements_is_read_the_same_by_the_edit_and_every_view(string provider)
    {
        // When the elements don't fit beside the kept codes, just the codes are kept and every element counts as had
        // (BUG-618). An element added later is judged that way by the edit too, so it can't unreport the case (blanking
        // the stored time) while the clocks, reminders and close gate still read it as fully reported.
        using var database = Open(provider);
        await using (var db = database.NewContext())
        {
            for (var i = 0; i < 100; i++)
                db.DataElements.Add(new DataElement
                {
                    Key = $"LONGELEMENTKEY{i:D3}", Label = $"Element {i}", NotificationJurisdictions = "", IsActive = true,
                    CreatedBy = "system", CreatedAtUtc = _clock.UtcNow,
                });
            await db.SaveChangesAsync();
        }
        var svc = Cases(database);
        var many = Enumerable.Range(0, 100).Select(i => $"LONGELEMENTKEY{i:D3}").Append("SSN").ToArray();
        var id = await SeedAsync(database, many);
        await svc.RecordNoticeAsync(id, "NY", _clock.UtcNow.AddHours(-2));
        (await LoadAsync(database, id)).ReportedJurisdictions.Should().Be("NY", "too long to keep the elements");

        await svc.UpdateImpactAssessmentAsync(id, 500, [.. many, "PASS"], null);

        var standing = (await Deadlines(database).EvaluateAsync(id)).Standing;
        var stored = (await LoadAsync(database, id)).ReportedAtUtc;
        stored.Should().Be(standing.ReportedAtUtc, "the edit and the views read the kept value the same way");
        (await ScanAsync(database)).ContainsKey(id).Should().Be(standing.Outstanding.Count > 0);
    }

    // The states a case can be in, set up on a fresh case each.
    private async Task<Guid> CaseInAsync(TestDatabase database, CaseService svc, string state)
    {
        var id = await SeedAsync(database, state == "whole, nothing in play" ? ["EMAIL"] : ["SSN", "DL"]);
        var (ny, ca) = (_clock.UtcNow.AddHours(-2), _clock.UtcNow.AddHours(-1));
        switch (state)
        {
            case "NY notified":
                await svc.RecordNoticeAsync(id, "NY", ny);
                break;
            case "both notified":
                await svc.RecordNoticeAsync(id, "NY", ny);
                await svc.RecordNoticeAsync(id, "CA", ca);
                break;
            case "legacy whole report":
                await LegacyReportAsync(database, id, ny, ["NY", "CA"]);
                break;
            case "whole, nothing in play":
                await svc.MarkReportedAsync(id, ny);
                break;
            case "TX brought in later":
                await svc.RecordNoticeAsync(id, "NY", ny);
                await svc.RecordNoticeAsync(id, "CA", ca);
                await svc.UpdateImpactAssessmentAsync(id, 500, ["SSN", "DL", "PASS"], null);
                break;
            case "CA's notice removed":
                await svc.RecordNoticeAsync(id, "NY", ny);
                await svc.RecordNoticeAsync(id, "CA", ca);
                await svc.RemoveNoticeAsync(id, "CA");
                break;
            case "Mark reported over NY":
                await svc.RecordNoticeAsync(id, "NY", ny);
                await svc.MarkReportedAsync(id, ca);
                break;
            case DriftState:   // CAP-38 review: a stored time over CA's running clock (an older build, a restore, a hand edit)
                await svc.RecordNoticeAsync(id, "NY", ny);
                await LegacyReportAsync(database, id, ca, null);
                break;
        }
        return id;
    }

    private const string DriftState = "stored time over a running clock";

    private static readonly string[] States =
    [
        "unreported", "NY notified", "both notified", "legacy whole report", "whole, nothing in play", "TX brought in later",
        "CA's notice removed", "Mark reported over NY", DriftState,
    ];

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_report_Briefing_gate_reminder_scan_and_register_agree_on_every_case(string provider)
    {
        using var database = Open(provider);
        var svc = Cases(database);
        var ids = new Dictionary<string, Guid>();
        foreach (var state in States) ids[state] = await CaseInAsync(database, svc, state);

        var reminded = await ScanAsync(database, new DeadlineReminderTracker());   // every clock is at risk: each running one is reminded
        var register = (await new LegalRegisterService(database.Factory(), _user, Deadlines(database), new ListedUserDirectory()).BuildAsync())
            .ToDictionary(r => r.CaseNumber);
        var read = new Dictionary<string, string>();
        foreach (var (state, id) in ids)
        {
            var briefing = await Deadlines(database).EvaluateAsync(id);
            read[state] = briefing.Standing.IsFullyReported ? "fully" : briefing.Standing.IsPartlyReported ? "partly" : "not";
            var model = await Reports(database).BuildPreviewModelAsync(id, null);
            var row = register[model.CaseNumber];
            var running = Running(briefing);
            var fully = briefing.Standing.IsFullyReported;

            running.Should().Equal(briefing.Standing.Outstanding.Order(StringComparer.Ordinal), $"{state}: a clock runs exactly where a notice is owed");
            reminded.GetValueOrDefault(id, []).Should().Equal(running, $"{state}: the scan reminds about each running clock, and only those");
            (await GateMetAsync(database, id)).Should().Be(running.Count == 0, $"{state}: the close gate waits on exactly the owed notices");
            (model.ReportedAtUtc is not null).Should().Be(fully, $"{state}: the report says reported only when every regulator was told");
            model.NotificationStanding.Should().Be(NoticeDetailText.Standing(briefing, Utc), $"{state}: the report and the Briefing say the same");
            (row.ReportedAtUtc is not null).Should().Be(fully, $"{state}: the register too");
            row.PartlyReported.Should().Be(briefing.Standing.IsPartlyReported, $"{state}: the register too");
            // CAP-38 review: the report's own "Reported" lines and the timeline's reported milestone agree with its standing.
            model.OutcomeStamps.Any(s => s.StartsWith("Reported to regulators", StringComparison.Ordinal)).Should().Be(fully, $"{state}: the outcome stamp too");
            (ReportTemplateFields.Scalar(model, "case.reported") != "").Should().Be(fully, $"{state}: case.reported too");
            var full = await LoadAsync(database, id);
            CaseMilestones.Project(full, new MilestoneLabels(x => "", s => "", p => "", m => "", Standing: briefing.Standing))
                .Any(m => m.Key.StartsWith("reported:", StringComparison.Ordinal)).Should().Be(fully, $"{state}: the reported milestone too");
            if (state != DriftState)
                full.ReportedAtUtc.Should().Be(briefing.Standing.ReportedAtUtc, $"{state}: the stored time follows the notices");
        }
        // And the states read as they should.
        read.Should().Equal(new Dictionary<string, string>
        {
            ["unreported"] = "not", ["NY notified"] = "partly", ["both notified"] = "fully", ["legacy whole report"] = "fully",
            ["whole, nothing in play"] = "fully", ["TX brought in later"] = "partly", ["CA's notice removed"] = "partly",
            ["Mark reported over NY"] = "fully", [DriftState] = "partly",
        });
    }

    private sealed class StubSettings : INotificationDeadlineSettingsProvider
    {
        public NotificationDeadlineSettings Current { get; set; } = NotificationDeadlineSettings.Off;
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_reportDir)) Directory.Delete(_reportDir, recursive: true); }
        catch (IOException) { /* best effort */ }
    }
}
