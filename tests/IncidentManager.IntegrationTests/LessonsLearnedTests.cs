using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Lessons;
using IncidentManager.Application.Reporting;
using IncidentManager.Application.Security;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Reporting;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// E-26 / PROD-41: the post-incident review, improvement actions, the cross-case register, the close-gate
/// check, and the separate lessons-learned report.
/// </summary>
public sealed class LessonsLearnedTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 24, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();
    private readonly string _reportDir = Path.Combine(Path.GetTempPath(), "im-lessons-tests", Guid.NewGuid().ToString("N"));
    private readonly TestOptionsMonitor<ReportingOptions> _reporting = new(new ReportingOptions());

    public LessonsLearnedTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.IncidentCommander]; // edits + sees restricted cases
    }

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>()
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

    private LessonsService Lessons() => new(NewFactory(), _user, _clock, new IdUserDirectory());

    private CaseService Cases(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new StageGateEvaluator(), new TestSlaTargets());

    private ReportService Reports() =>
        new(NewFactory(), new ReportGenerator(),
            new FileReportStore(Microsoft.Extensions.Options.Options.Create(new ReportOutputOptions { RootPath = _reportDir })),
            _hasher, _user, _clock, new IncidentManager.Application.Content.MarkdownService(), _reporting,
            new FileReportBrandingStore(Microsoft.Extensions.Options.Options.Create(new ReportBrandingOptions { RootPath = Path.Combine(_reportDir, "branding") })),
            new IdUserDirectory(),
            new IncidentManager.Infrastructure.Severities.ConfigurationSeverityLabels(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()),
            diagrams: new IncidentManager.Infrastructure.Reporting.SkiaReportDiagrams());   // PROD-46: real pictures

    private async Task<Guid> NewCaseAsync(string name, Classification classification = Classification.Incident, bool exercise = false)
    {
        await using var db = NewContext();
        return (await Cases(db).CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = name, Title = name, Classification = classification, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, Summary = "Summary.", IsExercise = exercise
        })).Id;
    }

    private static ImprovementActionInput Action(string title, DateTimeOffset? target = null) =>
        new(title, "Remote access", null, "analyst1", target);

    [Fact]
    public async Task A_review_saves_and_a_stale_save_is_refused_rather_than_overwriting()
    {
        var id = await NewCaseAsync("Review Case");
        var svc = Lessons();

        await svc.SaveReviewAsync(id, new PostIncidentReviewInput("What happened.", "Factors.", null, null, false), expectedStamp: null);
        var first = (await svc.GetForCaseAsync(id)).Review!;
        first.WhatHappened.Should().Be("What happened.");
        first.IsRecorded.Should().BeTrue();

        // Another author saves on top of the first version…
        await svc.SaveReviewAsync(id, new PostIncidentReviewInput("Revised.", "Factors.", null, null, false), first.Stamp);

        // …so a save still holding the first stamp is refused instead of silently clobbering it.
        var stale = () => svc.SaveReviewAsync(id, new PostIncidentReviewInput("Mine.", null, null, null, false), first.Stamp);
        await stale.Should().ThrowAsync<StaleEditException>();
        (await svc.GetForCaseAsync(id)).Review!.WhatHappened.Should().Be("Revised.");

        // Both saves are in the tamper-evident audit trail.
        await using var db = NewContext();
        (await db.AuditLog.CountAsync(a => a.EntityType == nameof(PostIncidentReview))).Should().Be(2);
    }

    [Fact]
    public async Task Logging_an_action_clears_no_actions_identified_and_the_two_cannot_coexist()
    {
        var id = await NewCaseAsync("Flag Case");
        var svc = Lessons();
        await svc.SaveReviewAsync(id, new PostIncidentReviewInput("What happened.", null, null, null, NoActionsIdentified: true), null);

        await svc.AddActionAsync(id, Action("Extend MFA to the vendor portal"));

        var view = await svc.GetForCaseAsync(id);
        view.Review!.NoActionsIdentified.Should().BeFalse("logging an action answers the question the other way");
        view.Actions.Should().ContainSingle();

        var contradict = () => svc.SaveReviewAsync(id,
            new PostIncidentReviewInput("What happened.", null, null, null, NoActionsIdentified: true), view.Review.Stamp);
        await contradict.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Closing_an_action_needs_an_outcome_note_and_stamps_then_clears_the_close_time()
    {
        var id = await NewCaseAsync("Close Case");
        var svc = Lessons();
        var actionId = await svc.AddActionAsync(id, Action("Reconcile the vendor inventory"));

        var noNote = () => svc.UpdateActionAsync(id, actionId, Action("Reconcile the vendor inventory") with { Status = ImprovementActionStatus.Completed });
        await noNote.Should().ThrowAsync<ArgumentException>();

        await svc.UpdateActionAsync(id, actionId, Action("Reconcile the vendor inventory") with
        {
            Status = ImprovementActionStatus.Completed, OutcomeNote = "Inventory reconciled; ticket CHG-1."
        });
        var closed = (await svc.GetForCaseAsync(id)).Actions.Single();
        closed.ClosedAtUtc.Should().Be(_clock.UtcNow);

        // Reopening puts it back in the open register.
        await svc.UpdateActionAsync(id, actionId, Action("Reconcile the vendor inventory") with { Status = ImprovementActionStatus.InProgress });
        (await svc.GetForCaseAsync(id)).Actions.Single().ClosedAtUtc.Should().BeNull();
    }

    [Fact]
    public async Task Writes_need_EditCases_even_without_the_UI()
    {
        var id = await NewCaseAsync("Perm Case");
        _user.RoleSet = [AppRole.Manager]; // views everything, edits nothing

        var svc = Lessons();
        var save = () => svc.SaveReviewAsync(id, new PostIncidentReviewInput("x", null, null, null, false), null);
        var add = () => svc.AddActionAsync(id, Action("x"));
        await save.Should().ThrowAsync<ForbiddenException>();
        await add.Should().ThrowAsync<ForbiddenException>();
    }

    [Fact]
    public async Task A_restricted_case_is_invisible_to_someone_outside_its_need_to_know()
    {
        var id = await NewCaseAsync("Restricted Case");
        await Lessons().AddActionAsync(id, Action("Sensitive follow-up"));
        await using (var db = NewContext())
        {
            (await db.Cases.SingleAsync(c => c.Id == id)).IsRestricted = true;
            await db.SaveChangesAsync();
        }

        _user.UserId = "analyst2";
        _user.RoleSet = [AppRole.Analyst]; // not the IC, not assigned, no ViewRestricted
        var svc = Lessons();

        (await svc.GetForCaseAsync(id)).Actions.Should().BeEmpty();
        (await svc.GetRegisterAsync(new RegisterFilter(RegisterScope.All))).Rows.Should().BeEmpty();
        var add = () => svc.AddActionAsync(id, Action("x"));
        await add.Should().ThrowAsync<InvalidOperationException>().WithMessage("Case not found.");
    }

    [Fact]
    public async Task The_register_scopes_exercises_counts_and_past_target_actions()
    {
        var real = await NewCaseAsync("Real Case");
        var drill = await NewCaseAsync("Tabletop Case", exercise: true);
        var svc = Lessons();
        await svc.AddActionAsync(real, Action("Past target", _clock.UtcNow.AddDays(-3)));
        await svc.AddActionAsync(real, Action("On track", _clock.UtcNow.AddDays(10)));
        var done = await svc.AddActionAsync(real, Action("Done"));
        await svc.UpdateActionAsync(real, done, Action("Done") with { Status = ImprovementActionStatus.Completed, OutcomeNote = "Done." });
        await svc.AddActionAsync(drill, Action("From the tabletop"));

        var open = await svc.GetRegisterAsync(new RegisterFilter());
        open.Rows.Select(r => r.Action.Title).Should().BeEquivalentTo(["Past target", "On track"],
            "exercise cases are excluded by default and closed actions aren't open");
        open.Summary.Should().Be(new RegisterSummary(Open: 2, PastTarget: 1, CompletedLast12Months: 1, NotPursuedLast12Months: 0));

        (await svc.GetRegisterAsync(new RegisterFilter(RegisterScope.PastTarget))).Rows.Should().ContainSingle(r => r.Action.Title == "Past target");
        (await svc.GetRegisterAsync(new RegisterFilter(IncludeExercises: true))).Rows.Should().Contain(r => r.IsExercise);
        (await svc.GetRegisterAsync(new RegisterFilter(RegisterScope.All, Search: "tabletop", IncludeExercises: true))).Rows.Should().ContainSingle();
    }

    [Fact]
    public async Task The_register_csv_neutralises_formula_injection()
    {
        var id = await NewCaseAsync("Csv Case");
        await Lessons().AddActionAsync(id, new ImprovementActionInput("=HYPERLINK(\"http://x\")", "@SUM(1)", null, null, null));

        var csv = await Lessons().ExportRegisterCsvAsync(new RegisterFilter(RegisterScope.All));

        csv.Should().StartWith("Case,Case title,Exercise,Improvement action");
        csv.Should().Contain("'=HYPERLINK").And.Contain("'@SUM(1)");
    }

    [Fact]
    public async Task A_close_gate_requiring_lessons_blocks_an_incident_until_the_review_is_complete()
    {
        var id = await NewCaseAsync("Gate Case");
        await using (var db = NewContext())
        {
            var gate = new StageGate
            {
                Trigger = StageGateTrigger.CloseCase, Name = "Closure readiness", IsActive = true,
                CreatedBy = "system", CreatedAtUtc = _clock.UtcNow
            };
            gate.Requirements.Add(new StageGateRequirement
            {
                GateId = gate.Id, Order = 0, Kind = GateRequirementKind.MachineCheck,
                CheckKey = GateCheckKeys.LessonsCaptured, Label = "Lessons captured", IsBlocking = true
            });
            db.StageGates.Add(gate);
            await db.SaveChangesAsync();
        }

        var svc = Lessons();
        await using (var db = NewContext())
        {
            var close = () => Cases(db).ChangePhaseAsync(id, CasePhase.Closed, "done");
            await close.Should().ThrowAsync<GateNotSatisfiedException>("no review yet");

            // What happened alone isn't enough: the follow-up question must be answered too.
            await svc.SaveReviewAsync(id, new PostIncidentReviewInput("What happened.", null, null, null, false), null);
            await close.Should().ThrowAsync<GateNotSatisfiedException>();

            var stamp = (await svc.GetForCaseAsync(id)).Review!.Stamp;
            await svc.SaveReviewAsync(id, new PostIncidentReviewInput("What happened.", null, null, null, NoActionsIdentified: true), stamp);
            await Cases(db).ChangePhaseAsync(id, CasePhase.Closed, "done");
        }

        // Improvement actions stay editable after the case closes: follow-up work outlives the case.
        await svc.AddActionAsync(id, Action("Post-close follow-up"));
        (await svc.GetForCaseAsync(id)).Actions.Should().ContainSingle();
    }

    [Fact]
    public async Task The_lessons_report_is_stored_separately_from_the_case_report_and_carries_the_legend()
    {
        var id = await NewCaseAsync("Report Case");
        // The long fields are Markdown (edited like Notes); the report keeps the formatting, not the syntax.
        await Lessons().SaveReviewAsync(id, new PostIncidentReviewInput(
            "## Timeline\n**What** happened.\n\n- Credential reused\n  - from a *prior* breach\n\n1. Detect\n2. Contain\n\n> Vendor statement\n\n```\nrclone copy tenant:/ ./out\n```",
            null, null, null, false), null);
        await Lessons().AddActionAsync(id, Action("Extend MFA"));
        _reporting.CurrentValue.LessonsLegend = "Confidential - Prepared at the Direction of Counsel";

        var reports = Reports();
        var lessons = await reports.GenerateLessonsAsync(id);
        var caseReport = await reports.GenerateAsync(id);

        lessons.Kind.Should().Be(ReportKind.LessonsLearned);
        lessons.FileName.Should().Contain("lessons-learned").And.EndWith("_v1.docx");
        caseReport.Kind.Should().Be(ReportKind.Case);
        caseReport.Version.Should().Be(1, "versions number per kind");

        (await reports.ListAsync(id)).Should().ContainSingle(r => r.Id == caseReport.Id, "the case report list excludes the lessons report");
        (await reports.ListAsync(id, ReportKind.LessonsLearned)).Should().ContainSingle(r => r.Id == lessons.Id);

        // The lessons document has the review, the action, and the legend; the case report has none of them.
        var (_, lessonsStream) = await reports.OpenAsync(lessons.Id);
        var (_, caseStream) = await reports.OpenAsync(caseReport.Id);
        var lessonsText = DocxText(lessonsStream);
        var caseText = DocxText(caseStream);
        lessonsText.Should().Contain("What happened.").And.Contain("Extend MFA");
        lessonsText.Should().NotContain("**").And.NotContain("## ", "Markdown syntax never prints");
        lessonsText.Should().Contain("•").And.Contain("Credential reused");
        lessonsText.Should().Contain("◦").And.Contain("2.").And.Contain("rclone copy tenant:/ ./out");
        var (_, again) = await reports.OpenAsync(lessons.Id);
        DocxBoldRuns(again).Should().Contain("What").And.Contain("Timeline", "emphasis and headings print bold");

        // Schema-valid, so Word opens it without an "unreadable content" repair prompt.
        var (_, forValidation) = await reports.OpenAsync(lessons.Id);
        DocxSchemaErrors(forValidation).Should().BeEmpty();
        var (_, caseForValidation) = await reports.OpenAsync(caseReport.Id);
        DocxSchemaErrors(caseForValidation).Should().BeEmpty("the case report shares the same Word helpers");

        lessonsText.Should().Contain("Prepared at the Direction of Counsel");
        caseText.Should().NotContain("Extend MFA").And.NotContain("Prepared at the Direction of Counsel");

        // The gate's report count only counts case reports.
        await using var db = NewContext();
        (await db.Reports.CountAsync(r => r.CaseId == id && r.Kind == ReportKind.Case)).Should().Be(1);
    }

    [Fact]
    public async Task A_full_case_report_is_schema_valid_Word()
    {
        Guid id;
        await using (var db = NewContext())
        {
            await DevDataSeeder.SeedAsync(db, _clock);
            id = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
        }

        var reports = Reports();
        var report = await reports.GenerateAsync(id);
        var (_, stream) = await reports.OpenAsync(report.Id);

        DocxSchemaErrors(stream).Should().BeEmpty("Word should open the report without a repair prompt");
    }

    /// <summary>Open XML schema validation errors for a .docx (empty = Word opens it cleanly).</summary>
    private static List<string> DocxSchemaErrors(Stream s)
    {
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        s.Dispose();
        ms.Position = 0;
        using var doc = DocumentFormat.OpenXml.Packaging.WordprocessingDocument.Open(ms, false);
        return new DocumentFormat.OpenXml.Validation.OpenXmlValidator()
            .Validate(doc).Select(e => $"{e.Path?.XPath}: {e.Description}").ToList();
    }

    /// <summary>The text of every bold run in a .docx body.</summary>
    private static List<string> DocxBoldRuns(Stream s)
    {
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        s.Dispose();
        ms.Position = 0;
        using var doc = DocumentFormat.OpenXml.Packaging.WordprocessingDocument.Open(ms, false);
        return doc.MainDocumentPart!.Document.Body!.Descendants<DocumentFormat.OpenXml.Wordprocessing.Run>()
            .Where(r => r.RunProperties?.Bold is not null)
            .Select(r => r.InnerText)
            .ToList();
    }

    /// <summary>Body + header text of a .docx (headers are separate parts).</summary>
    private static string DocxText(Stream s)
    {
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        s.Dispose();
        ms.Position = 0;
        using var doc = DocumentFormat.OpenXml.Packaging.WordprocessingDocument.Open(ms, false);
        var main = doc.MainDocumentPart!;
        return string.Join("\n", new[] { main.Document.Body!.InnerText }
            .Concat(main.HeaderParts.Select(h => h.Header.InnerText)));
    }

    private sealed class IdUserDirectory : IUserDirectory
    {
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<UserSummary> All() => [];
        public UserSummary? Resolve(string userId) => null;
        public string DisplayFor(string? userId) => userId ?? "—";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
    }


    public void Dispose()
    {
        _connection.Dispose();
        try { Directory.Delete(_reportDir, recursive: true); } catch { /* best effort */ }
    }
}
