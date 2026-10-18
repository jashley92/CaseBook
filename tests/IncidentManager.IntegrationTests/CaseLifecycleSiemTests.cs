using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Reporting;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using IncidentManager.Infrastructure.Storage;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>A sink that fails every emit, to show a SIEM failure never fails the action that produced the event.</summary>
internal sealed class ThrowingSecurityEventSink : ISecurityEventSink
{
    public int Attempts { get; private set; }
    public void Emit(SecurityEvent e)
    {
        Attempts++;
        throw new InvalidOperationException("SIEM queue unavailable");
    }
}

/// <summary>
/// CAP-06: the case lifecycle (5506-5515) and reference-data changes (5405) reach the SIEM stream, after the save, with
/// the case number, the actor and the detection id, ids and labels only; and a sink that fails never fails the action.
/// </summary>
public sealed class CaseLifecycleSiemTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 1, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.IncidentCommander, AppRole.SysAdmin] };
    private readonly CapturingSecurityEventSink _siem = new();
    private readonly string _workDir = Path.Combine(Path.GetTempPath(), "im-cap06", Guid.NewGuid().ToString("N"));

    public CaseLifecycleSiemTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
        DevDataSeeder.SeedCaseOutcomesAsync(db, _clock).GetAwaiter().GetResult();
    }

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
        .Options;

    private TestDbContextFactory Factory() => new(Options());

    private CaseService Cases(ISecurityEventSink? siem = null)
    {
        var db = new AppDbContext(Options());
        return new CaseService(Factory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
            siem ?? _siem);
    }

    private async Task<Case> OpenAsync(CaseService svc, Classification? cls = Classification.Incident, bool exercise = false,
        string? detection = "XSIAM-4412") =>
        await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Takeover", Title = "Impossible-travel sign-in", Classification = cls,
            Severity = Severity.High, Origin = CaseOrigin.InternalDetection, Summary = "XSIAM flagged an impossible-travel sign-in.",
            DetectionCaseId = detection, IsExercise = exercise
        });

    private SecurityEvent Only(int id) => _siem.Events.Should().ContainSingle(e => e.EventId == id).Subject;

    [Fact]
    public async Task Filing_a_case_emits_5506_with_its_number_the_actor_and_the_detection_id()
    {
        var c = await OpenAsync(Cases());

        var e = Only(SecurityEventIds.CaseCreated);
        e.CaseNumber.Should().Be(c.CaseNumber);
        e.Actor.Should().Be(_user.UserId);
        e.ActorUpn.Should().Be(_user.UserPrincipalName);
        e.Category.Should().Be("Governance");
        e.Severity.Should().Be(SecuritySeverity.Info);
        e.Detail.Should().Be("classification=Incident severity=High detection=XSIAM-4412");
        e.Detail.Should().NotContain("impossible-travel", "events carry ids and labels, never the case's text");
    }

    [Fact]
    public async Task Moving_closing_and_reopening_emit_5507_5509_and_5510_and_never_both_for_one_move()
    {
        var svc = Cases();
        var c = await OpenAsync(svc);
        await svc.ChangePhaseAsync(c.Id, CasePhase.Triage, null);
        await svc.ChangePhaseAsync(c.Id, CasePhase.Triage, null);   // no move, no event
        _clock.UtcNow = _clock.UtcNow.AddHours(1);
        await svc.ChangePhaseAsync(c.Id, CasePhase.Closed, null, closing: TestOutcomes.Closing());
        await svc.ReopenAsync(c.Id, "New evidence came in");

        Only(SecurityEventIds.CasePhaseChanged).Detail.Should().StartWith("from=New to=Triage");
        var closed = Only(SecurityEventIds.CaseClosed);
        closed.Detail.Should().Be($"outcome={CaseOutcomeCatalog.Confirmed} detection=XSIAM-4412");
        closed.Severity.Should().Be(SecuritySeverity.Info, "it met its gate (there's none here)");
        Only(SecurityEventIds.CaseReopened).Severity.Should().Be(SecuritySeverity.Info);
        _siem.Events.Should().NotContain(e => e.Detail != null && e.Detail.Contains("New evidence"), "the reason stays in the audit trail");
    }

    [Fact]
    public async Task Closing_past_an_unmet_gate_is_a_Warning_that_says_so()
    {
        var gates = new StageGateService(Factory(), _user, _clock, _siem);
        await gates.CreateAsync(new StageGateInput(StageGateTrigger.CloseCase, "Closure checks", null, true,
            [new GateRequirementInput(GateRequirementKind.Attestation, null, null, "Post-incident review complete", true)]));
        var svc = Cases();
        var c = await OpenAsync(svc);
        _clock.UtcNow = _clock.UtcNow.AddHours(1);

        await svc.ChangePhaseAsync(c.Id, CasePhase.Closed, null, overrideJustification: "Review is booked for next week",
            closing: TestOutcomes.Closing());

        var e = Only(SecurityEventIds.CaseClosed);
        e.Severity.Should().Be(SecuritySeverity.Warning);
        e.Detail.Should().Contain("gateOverridden=true").And.NotContain("booked");
    }

    [Fact]
    public async Task A_reclassification_emits_5508_a_lowering_is_a_Warning_and_a_breach_escalation_stays_5503()
    {
        var svc = Cases();
        var c = await OpenAsync(svc, Classification.AdverseEvent);
        await svc.ReclassifyAsync(c.Id, Classification.Incident, "Confirmed compromise");
        await svc.ReclassifyAsync(c.Id, Classification.AdverseEvent, "Turned out to be a test account");
        await svc.ReclassifyAsync(c.Id, Classification.Breach, "Customer data left");

        var moves = _siem.Events.Where(e => e.EventId == SecurityEventIds.CaseReclassified).ToList();
        moves.Should().HaveCount(2, "the escalation to Breach is 5503's");
        moves[0].Action.Should().Be("CaseReclassified");
        moves[0].Severity.Should().Be(SecuritySeverity.Info);
        moves[0].Detail.Should().StartWith("from=AdverseEvent to=Incident");
        moves[1].Action.Should().Be("CaseDowngraded");
        moves[1].Severity.Should().Be(SecuritySeverity.Warning);
        Only(SecurityEventIds.BreachEscalated);
    }

    [Fact]
    public async Task Materiality_reporting_and_archiving_emit_5512_5513_and_5511()
    {
        var svc = Cases();
        var c = await OpenAsync(svc, detection: null);
        await svc.RecordMaterialityAsync(c.Id, MaterialityStatus.Material, "Disclosure committee", _clock.UtcNow, "Customer data");
        await svc.MarkReportedAsync(c.Id, _clock.UtcNow);
        await svc.SetArchivedAsync(c.Id, true);
        await svc.SetArchivedAsync(c.Id, true);   // already archived: nothing happened, nothing sent
        await svc.SetArchivedAsync(c.Id, false);

        var m = Only(SecurityEventIds.MaterialityRecorded);
        m.Detail.Should().Be("status=Material", "no detection id on this case, and never the rationale");
        m.Severity.Should().Be(SecuritySeverity.Warning);
        Only(SecurityEventIds.CaseReported).Action.Should().Be("CaseReported");
        var archive = _siem.Events.Where(e => e.EventId == SecurityEventIds.CaseArchived).ToList();
        archive.Select(e => (e.Action, e.Severity)).Should().Equal(
            ("CaseArchived", SecuritySeverity.Info), ("CaseRestored", SecuritySeverity.Warning));
    }

    [Fact]
    public async Task An_exercise_is_sent_marked_EXERCISE()
    {
        await OpenAsync(Cases(), exercise: true);
        Only(SecurityEventIds.CaseCreated).Detail.Should().StartWith(ExerciseMarking.Prefix);
    }

    [Fact]
    public async Task A_sink_that_fails_never_fails_the_case_action()
    {
        var failing = new ThrowingSecurityEventSink();
        var svc = Cases(failing);
        var c = await OpenAsync(svc);
        await svc.ChangePhaseAsync(c.Id, CasePhase.Triage, null);
        await svc.SetArchivedAsync(c.Id, true);

        failing.Attempts.Should().Be(3);
        await using var db = new AppDbContext(Options());
        (await db.Cases.SingleAsync(x => x.Id == c.Id)).IsArchived.Should().BeTrue();
    }

    [Fact]
    public async Task Approving_a_report_emits_5514_naming_the_report()
    {
        var svc = Cases();
        var c = await OpenAsync(svc);
        var reportDir = Path.Combine(_workDir, "reports");
        var reports = new IncidentManager.Application.Reporting.ReportService(Factory(), new ReportGenerator(),
            new IncidentManager.Infrastructure.Storage.FileReportStore(Microsoft.Extensions.Options.Options.Create(new ReportOutputOptions { RootPath = reportDir })),
            _hasher, _user, _clock, new IncidentManager.Application.Content.MarkdownService(),
            new TestOptionsMonitor<IncidentManager.Application.Reporting.ReportingOptions>(new()),
            new IncidentManager.Infrastructure.Storage.FileReportBrandingStore(Microsoft.Extensions.Options.Options.Create(
                new ReportBrandingOptions { RootPath = Path.Combine(reportDir, "branding") })),
            new ListedUserDirectory(),
            new IncidentManager.Infrastructure.Severities.ConfigurationSeverityLabels(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()),
            siem: _siem);
        var draft = await reports.GenerateAsync(c.Id);
        await reports.ApproveAsync(draft.Id);

        var e = Only(SecurityEventIds.ReportApproved);
        e.CaseNumber.Should().Be(c.CaseNumber);
        e.TargetType.Should().Be("Report");
        e.TargetId.Should().Be(draft.Id.ToString());
    }

    // ── 5405: every admin reference-data service ─────────────────────────────────────────────────────────────

    private List<SecurityEvent> RefData() => _siem.Events.Where(e => e.EventId == SecurityEventIds.ReferenceDataChanged).ToList();

    [Fact]
    public async Task Stage_gates_emit_5405_as_Warnings_for_create_change_and_delete()
    {
        var svc = new StageGateService(Factory(), _user, _clock, _siem);
        var input = new StageGateInput(StageGateTrigger.EscalateToIncident, "Incident checks", null, true,
            [new GateRequirementInput(GateRequirementKind.Attestation, null, null, "Scope agreed", true)]);
        var id = await svc.CreateAsync(input);
        await svc.UpdateAsync(id, input with { IsActive = false });
        await svc.DeleteAsync(id);

        RefData().Select(e => (e.Action, e.TargetType, e.Detail, e.Severity)).Should().Equal(
            ("ReferenceDataCreated", ReferenceDataKinds.StageGate, "Incident checks", SecuritySeverity.Warning),
            ("ReferenceDataChanged", ReferenceDataKinds.StageGate, "Incident checks (inactive)", SecuritySeverity.Warning),
            ("ReferenceDataDeleted", ReferenceDataKinds.StageGate, "Incident checks", SecuritySeverity.Warning));
        RefData().Should().OnlyContain(e => e.TargetId == id.ToString() && e.Actor == _user.UserId && e.Category == "Admin");
    }

    [Fact]
    public async Task Data_elements_emit_5405_naming_changed_jurisdictions_and_a_reorder_once()
    {
        var svc = new DataElementService(Factory(), _user, _clock, _siem);
        await svc.SaveAsync([new DataElementRow(null, "Health record", "NY"), new DataElementRow(null, "Passport", null)]);
        var rows = await svc.ListAllAsync();
        var health = rows.Single(r => r.Label == "Health record");
        var passport = rows.Single(r => r.Label == "Passport");
        _siem.Events.Clear();

        await svc.SaveAsync([new DataElementRow(passport.Id, "Passport", null), new DataElementRow(health.Id, "Health record", "NY,CA")]);
        await svc.SetArchivedAsync(passport.Id, true);
        await svc.DeleteAsync(passport.Id);

        RefData().Select(e => (e.Action, e.Detail)).Should().Equal(
            ("ReferenceDataChanged", "Health record (jurisdictions: NY,CA)"),
            ("ReferenceDataChanged", "(display order)"),
            ("ReferenceDataChanged", "Passport (archived)"),
            ("ReferenceDataDeleted", "Passport"));
        RefData().Take(1).Should().OnlyContain(e => e.Severity == SecuritySeverity.Info);
        RefData().Last().Severity.Should().Be(SecuritySeverity.Warning, "a delete is a Warning");
    }

    [Fact]
    public async Task Outcomes_playbooks_profiles_and_deadline_rules_emit_5405()
    {
        var outcomes = new CaseOutcomeService(Factory(), _user, _clock, _siem);
        var current = await outcomes.ListActiveAsync();
        await outcomes.SaveAsync([.. current.Select(o => new CaseOutcomeRow(o.Id, o.Label, o.Description)), new CaseOutcomeRow(null, "Insider misuse", null)]);

        var templates = new CaseTemplateService(Factory(), _user, _clock, _siem);
        var playbook = await templates.CreateAsync(new TemplateInput("Phishing playbook", null, true, 1, null, null, null, null,
            [new TemplateStepInput("Pull the lure", null, null, null)]));
        await templates.DeleteAsync(playbook);

        var profiles = new ReportProfileService(Factory(), _user, _clock, _siem);
        await profiles.CreateAsync(new ReportProfileInput("Executive summary", null, true, 1, null));

        var rules = new NotificationRuleService(Factory(), _user, _clock, _siem);
        await rules.SaveAsync(null, "TX", "Texas", 60 * 24);

        RefData().Select(e => (e.TargetType, e.Action, e.Detail)).Should().Equal(
            (ReferenceDataKinds.CaseOutcome, "ReferenceDataCreated", "Insider misuse"),
            (ReferenceDataKinds.CaseTemplate, "ReferenceDataCreated", "Phishing playbook"),
            (ReferenceDataKinds.CaseTemplate, "ReferenceDataDeleted", "Phishing playbook"),
            (ReferenceDataKinds.ReportProfile, "ReferenceDataCreated", "Executive summary"),
            (ReferenceDataKinds.DeadlineRule, "ReferenceDataCreated", "TX (1440 h)"));
        RefData().Single(e => e.TargetType == ReferenceDataKinds.DeadlineRule).Severity.Should().Be(SecuritySeverity.Warning);
    }

    private sealed class NoOpReloader : ISettingsReloader { public void Reload() { } }

    [Fact]
    public async Task Taxonomy_and_email_templates_emit_5405_by_key_never_their_text()
    {
        var taxonomy = new TaxonomyAdminService(Factory(), _clock, _user, new NoOpReloader(), _siem);
        await taxonomy.SetLabelAsync("Classification", "Breach", "Major incident");
        await taxonomy.SetVisibilityOrderAsync("EntityDisposition",
            ["Malicious", "Benign", "Unknown", "Suspicious", "Compromised"], ["Suspicious"]);
        var email = new EmailTemplateAdminService(Factory(), _clock, _user, new NoOpReloader(), _siem);
        await email.SaveAsync("assignment", "Secret project {{CaseNumber}}", "<p>Hi</p>");
        await email.ResetAsync("assignment");

        RefData().Select(e => (e.TargetType, e.Detail)).Should().Equal(
            (ReferenceDataKinds.TaxonomyLabel, "Classification:Label:Breach"),
            (ReferenceDataKinds.TaxonomyOrder, "EntityDisposition (1 hidden)"),
            (ReferenceDataKinds.EmailTemplate, "assignment"),
            (ReferenceDataKinds.EmailTemplate, "assignment (reset to the built-in)"));
        _siem.Events.Should().NotContain(e => e.Detail != null && (e.Detail.Contains("Major") || e.Detail.Contains("Secret")));
    }

    [Fact]
    public async Task Word_templates_emit_5405()
    {
        var engine = new WordTemplateEngine();
        var store = new IncidentManager.Infrastructure.Storage.FileReportTemplateStore(
            Microsoft.Extensions.Options.Options.Create(new ReportTemplateOptions { RootPath = Path.Combine(_workDir, "templates") }),
            Microsoft.Extensions.Options.Options.Create(new ReportBrandingOptions()));
        var svc = new ReportTemplateService(Factory(), _user, _clock, engine, store, _siem);
        var upload = await svc.UploadAsync("Examiner pack", "examiner.docx", engine.Starter());
        await svc.RenameAsync(upload.Id!.Value, "Examiner pack v2");
        await svc.SetActiveAsync(upload.Id!.Value, false);
        await svc.DeleteAsync(upload.Id!.Value);

        RefData().Select(e => (e.Action, e.Detail)).Should().Equal(
            ("ReferenceDataCreated", "Examiner pack"),
            ("ReferenceDataChanged", "Examiner pack v2"),
            ("ReferenceDataChanged", "Examiner pack v2 (archived)"),
            ("ReferenceDataDeleted", "Examiner pack v2"));
        RefData().Should().OnlyContain(e => e.TargetType == ReferenceDataKinds.ReportTemplate);
    }

    [Fact]
    public async Task A_sink_that_fails_never_fails_an_admin_save()
    {
        var failing = new ThrowingSecurityEventSink();
        var svc = new StageGateService(Factory(), _user, _clock, failing);
        var id = await svc.CreateAsync(new StageGateInput(StageGateTrigger.EscalateToIncident, "Incident checks", null, true, []));

        failing.Attempts.Should().Be(1);
        (await svc.GetAsync(id)).Should().NotBeNull();
    }

    public void Dispose()
    {
        _connection.Dispose();
        try { if (Directory.Exists(_workDir)) Directory.Delete(_workDir, recursive: true); }
        catch (IOException) { /* best effort */ }
    }
}
