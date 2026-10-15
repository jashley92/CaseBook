using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Reporting;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>E-28: admin-authored report profiles + per-case section layout override, and the U-37 preview model.</summary>
public sealed class ReportProfileTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();
    private readonly TestOptionsMonitor<ReportingOptions> _reporting = new(new ReportingOptions());
    private readonly string _reportDir;

    public ReportProfileTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _reportDir = Path.Combine(Path.GetTempPath(), "im-report-profile-tests", Guid.NewGuid().ToString("N"));
        _user.RoleSet = [AppRole.IncidentCommander, AppRole.SysAdmin]; // profile admin writes assert Administer (F-23)
        using (NewContext()) { } // build the schema on the shared in-memory connection
    }

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options);

    private ReportProfileService NewProfileService() => new(NewFactory(), _user, _clock);

    private IncidentManager.Application.Cases.CaseService NewCaseService() => new(
        NewFactory(), _user, _clock, new CaseNumberGenerator(NewContext()),
        new IncidentManager.Application.Cases.CreateCaseValidator(), new NoOpCaseNotifications(),
        new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private ReportService NewReportService(IncidentManager.Application.Abstractions.IOrganizationTimeZone? zone = null)
    {
        var store = new FileReportStore(Options.Create(new ReportOutputOptions { RootPath = _reportDir }));
        var branding = new FileReportBrandingStore(Options.Create(new ReportBrandingOptions { RootPath = Path.Combine(_reportDir, "branding") }));
        return new ReportService(NewFactory(), new ReportGenerator(), store, _hasher, _user, _clock,
            new IncidentManager.Application.Content.MarkdownService(), _reporting, branding, new StubUserDirectory(),
            new IncidentManager.Infrastructure.Severities.ConfigurationSeverityLabels(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()),
            zone: zone);
    }

    private sealed class NewYork : IncidentManager.Application.Abstractions.IOrganizationTimeZone
    {
        public TimeZoneInfo Current { get; } = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");
    }

    [Fact]
    public async Task A_due_date_prints_as_the_day_picked_not_the_utc_day(/* WF-36 */)
    {
        var caseId = await SeededCaseIdAsync();
        using (var db = NewContext())
        {
            // Due 15 Oct, picked in New York: stored as 23:59 there, which is 16 Oct in UTC.
            db.ActionItems.Add(new IncidentManager.Domain.Entities.ActionItem { CaseId = caseId, Title = "Rotate keys", DueAtUtc = new DateTimeOffset(2026, 10, 16, 3, 59, 0, TimeSpan.Zero),
                CreatedBy = "analyst1", CreatedAtUtc = _clock.UtcNow });
            db.SaveChanges();
        }

        var model = await NewReportService(new NewYork()).BuildPreviewModelAsync(caseId, null);

        var due = model.ActionItems.Single(a => a.Title == "Rotate keys");
        IncidentManager.Application.Reporting.ReportTemplateFields.CollectionFor("action.due").Should().NotBeNull();
        due.DueAtUtc!.Value.DateTime.Date.Should().Be(new DateTime(2026, 10, 15));
        due.DueAtUtc.Value.UtcDateTime.Should().Be(new DateTime(2026, 10, 16, 3, 59, 0), "the instant is unchanged");
    }

    /// <summary>Identity directory stub: resolves ids to themselves — enough for the report footer/owner columns.</summary>
    private sealed class StubUserDirectory : IncidentManager.Application.Abstractions.IUserDirectory
    {
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<IncidentManager.Application.Abstractions.UserSummary> All() => Array.Empty<IncidentManager.Application.Abstractions.UserSummary>();
        public IncidentManager.Application.Abstractions.UserSummary? Resolve(string userId) => null;
        public string DisplayFor(string? userId) => userId ?? "—";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
    }

    private async Task<Guid> SeededCaseIdAsync()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        return (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
    }

    // "Summary + Outcome only" — every other section explicitly hidden.
    private const string ExecLayout =
        "Summary,Outcome,!BusinessImpact,!EventTimeline,!InvestigationTimeline,!SystemsReviewed,!Indicators,!Recommendations,!Appendix";

    [Fact]
    public async Task Create_rejects_a_duplicate_name_and_update_round_trips()
    {
        var svc = NewProfileService();
        var id = await svc.CreateAsync(new ReportProfileInput("Executive summary", "Exec", true, 1, ExecLayout));

        var dup = async () => await svc.CreateAsync(new ReportProfileInput("Executive summary", null, true, 2, null));
        await dup.Should().ThrowAsync<InvalidOperationException>();

        await svc.UpdateAsync(id, new ReportProfileInput("Exec summary", "renamed", false, 5, ExecLayout));
        var got = await svc.GetAsync(id);
        got!.Name.Should().Be("Exec summary");
        got.IsActive.Should().BeFalse();
        got.SortOrder.Should().Be(5);
        ReportLayout.Resolve(got.SectionLayout).Should().Equal(ReportSection.Summary, ReportSection.Outcome);
    }

    [Fact]
    public async Task ListActive_hides_inactive_profiles()
    {
        var svc = NewProfileService();
        await svc.CreateAsync(new ReportProfileInput("Active one", null, true, 1, null));
        await svc.CreateAsync(new ReportProfileInput("Retired one", null, false, 2, null));

        (await svc.ListActiveAsync()).Select(p => p.Name).Should().ContainSingle().Which.Should().Be("Active one");
        (await svc.ListAllAsync()).Should().HaveCount(2);
    }

    [Fact]
    public async Task Case_profile_overrides_the_global_section_layout_when_generating()
    {
        var caseId = await SeededCaseIdAsync();
        var profileId = await NewProfileService().CreateAsync(
            new ReportProfileInput("Executive summary", null, true, 1, ExecLayout));

        await NewCaseService().SetReportProfileAsync(caseId, profileId);

        var svc = NewReportService();
        var report = await svc.GenerateAsync(caseId);
        var xml = await ReadWordXmlAsync(svc, report.Id);

        xml.Should().Contain("Summary");
        xml.Should().Contain("Outcome");
        // The hidden sections must not render as headings.
        xml.Should().NotContain("Appendix");
        xml.Should().NotContain("Event Timeline");
    }

    [Fact]
    public async Task No_profile_falls_back_to_the_global_default_all_sections()
    {
        var caseId = await SeededCaseIdAsync();

        var svc = NewReportService();
        var report = await svc.GenerateAsync(caseId);
        var xml = await ReadWordXmlAsync(svc, report.Id);

        // Global default (blank layout) = every section, so the Appendix is present.
        xml.Should().Contain("Appendix");
        xml.Should().Contain("Event Timeline");
    }

    [Fact]
    public async Task The_report_timeline_has_each_regulators_notice(/* WF-35 */)
    {
        var caseId = await SeededCaseIdAsync();
        using (var db = NewContext())
        {
            var c = db.Cases.Include(x => x.JurisdictionNotices).Single(x => x.Id == caseId);
            var at = c.DetectedAtUtc ?? c.CreatedAtUtc;
            c.RecordNotice("NY", at.AddHours(1), "analyst1", at.AddDays(3));
            c.RecordNotice("CA", at.AddDays(2), "analyst1", at.AddDays(3));
            db.SaveChanges();
        }

        var model = await NewReportService().BuildPreviewModelAsync(caseId, null);

        model.InvestigationTimeline.Select(i => i.Description).Should().Contain(d => d.Contains("Notified NY"))
            .And.Contain(d => d.Contains("Notified CA"));
    }

    [Fact]
    public async Task The_working_assessment_is_in_the_timeline_only_with_the_case_brief(/* WF-34 */)
    {
        var caseId = await SeededCaseIdAsync();
        Guid? current;
        using (var db = NewContext()) current = db.CaseBriefs.Where(b => b.CaseId == caseId && b.IsCurrent).Select(b => (Guid?)b.Id).FirstOrDefault();
        await NewCaseService().ReviseBriefAsync(caseId, current, "Phishing reached Finance", "Probably MFA fatigue", null, null);

        var plain = await NewReportService().BuildPreviewModelAsync(caseId, null);
        plain.InvestigationTimeline.Should().NotContain(i => i.Description.Contains("MFA fatigue"), "the brief is off by default (decision 0012)");

        var withBrief = await NewProfileService().CreateAsync(new ReportProfileInput("With brief", null, true, 1, "Summary,CaseBrief"));
        (await NewReportService().BuildPreviewModelAsync(caseId, withBrief)).InvestigationTimeline
            .Should().Contain(i => i.Description.Contains("MFA fatigue"));
    }

    [Fact]
    public async Task A_deleted_profile_transparently_falls_back_to_the_global_default()
    {
        var caseId = await SeededCaseIdAsync();
        var profiles = NewProfileService();
        var profileId = await profiles.CreateAsync(new ReportProfileInput("Executive summary", null, true, 1, ExecLayout));
        await NewCaseService().SetReportProfileAsync(caseId, profileId);
        await profiles.DeleteAsync(profileId); // case still holds the now-dangling id

        var model = await NewReportService().BuildPreviewModelAsync(caseId, profileId);
        // Resolver couldn't find the (deleted) profile → global default → all sections incl. Appendix.
        model.Sections.Should().Contain(ReportSection.Appendix);
    }

    [Fact]
    public async Task Preview_model_reflects_the_selected_profile_without_persisting()
    {
        var caseId = await SeededCaseIdAsync();
        var profileId = await NewProfileService().CreateAsync(
            new ReportProfileInput("Executive summary", null, true, 1, ExecLayout));

        // Preview with the profile selected but NOT saved on the case.
        var preview = await NewReportService().BuildPreviewModelAsync(caseId, profileId);
        preview.Sections.Should().Equal(ReportSection.Summary, ReportSection.Outcome);

        // The case itself is untouched → its own preview (no override) still shows all sections.
        var baseline = await NewReportService().BuildPreviewModelAsync(caseId, null);
        baseline.Sections.Should().Contain(ReportSection.Appendix);

        await using var db = NewContext();
        (await db.Cases.FirstAsync(c => c.Id == caseId)).ReportProfileId.Should().BeNull();
    }

    [Fact]
    public async Task Setting_a_profile_is_audited_and_the_chain_stays_valid()
    {
        var caseId = await SeededCaseIdAsync();
        var profileId = await NewProfileService().CreateAsync(new ReportProfileInput("Exec", null, true, 1, ExecLayout));

        await NewCaseService().SetReportProfileAsync(caseId, profileId);

        await using var db = NewContext();
        // The Case Update that set the profile produced an audit entry.
        var caseNumber = (await db.Cases.FirstAsync(c => c.Id == caseId)).CaseNumber;
        (await db.AuditLog.CountAsync(a => a.CaseNumber == caseNumber && a.EntityType == "Case" && a.Action == AuditAction.Update))
            .Should().BeGreaterThan(0);
        // Chain integrity holds end to end.
        var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task An_edit_opened_before_another_admins_save_is_refused_rather_than_undoing_it(/* BUG-349 */)
    {
        var svc = NewProfileService();
        var id = await svc.CreateAsync(new ReportProfileInput("Executive summary", null, true, 1, ExecLayout));
        var opened = (await svc.GetAsync(id))!;

        // Another admin archives the profile; this editor still holds the active copy.
        await svc.UpdateAsync(id, new ReportProfileInput("Executive summary", null, false, 1, ExecLayout), opened.Stamp);
        var stale = async () => await svc.UpdateAsync(id,
            new ReportProfileInput("Executive summary", "notes", true, 1, ExecLayout), opened.Stamp);

        (await stale.Should().ThrowAsync<InvalidOperationException>()).WithMessage("Someone changed the report profile*");
        (await svc.GetAsync(id))!.IsActive.Should().BeFalse("the other admin's archive stands");
    }

    [Fact]
    public async Task A_change_to_only_the_word_template_also_makes_an_open_edit_stale(/* BUG-349 */)
    {
        var svc = NewProfileService();
        var id = await svc.CreateAsync(new ReportProfileInput("Executive summary", null, true, 1, ExecLayout));
        var opened = (await svc.GetAsync(id))!;
        var templateId = Guid.NewGuid();
        using (var db = NewContext())
        {
            // The template id is outside the row hash (PROD-47), so the stamp has to cover it separately.
            db.ReportTemplates.Add(new IncidentManager.Domain.Entities.ReportTemplate
                { Id = templateId, Name = "House style", FileName = "house.docx", Sha256 = "00",
                  IsActive = true, CreatedBy = "admin2", CreatedAtUtc = _clock.UtcNow });
            db.SaveChanges();
        }
        await svc.UpdateAsync(id, new ReportProfileInput("Executive summary", null, true, 1, ExecLayout, templateId), opened.Stamp);

        var stale = async () => await svc.UpdateAsync(id,
            new ReportProfileInput("Executive summary", "notes", true, 1, ExecLayout), opened.Stamp);

        await stale.Should().ThrowAsync<InvalidOperationException>();
        (await svc.GetAsync(id))!.TemplateId.Should().Be(templateId);
    }

    [Fact]
    public async Task A_profile_picks_its_template_under_the_library_gate_so_an_archive_cant_slip_between(/* BUG-524 */)
    {
        var svc = NewProfileService();
        var id = await svc.CreateAsync(new ReportProfileInput("Executive summary", null, true, 1, ExecLayout));
        var opened = (await svc.GetAsync(id))!;
        var templateId = Guid.NewGuid();
        using (var db = NewContext())
        {
            db.ReportTemplates.Add(new IncidentManager.Domain.Entities.ReportTemplate
                { Id = templateId, Name = "House style", FileName = "house.docx", Sha256 = "00",
                  IsActive = true, CreatedBy = "admin2", CreatedAtUtc = _clock.UtcNow });
            db.SaveChanges();
        }

        // An archive holds the library gate while it checks no profile uses the template, then saves; the profile's
        // "is it active" check and save wait for it, so they see the archive and refuse, instead of passing just before it.
        Task update, create;
        using (await ReportTemplateService.EnterFileGateAsync())
        {
            update = Task.Run(() => svc.UpdateAsync(id, new ReportProfileInput("Executive summary", null, true, 1, ExecLayout, templateId), opened.Stamp));
            create = Task.Run(() => svc.CreateAsync(new ReportProfileInput("Full pack", null, true, 2, ExecLayout, templateId)));
            await Task.Delay(200);
            update.IsCompleted.Should().BeFalse("the template check and the save wait for the library gate");
            create.IsCompleted.Should().BeFalse();
            using var db = NewContext();
            (await db.ReportTemplates.SingleAsync(t => t.Id == templateId)).IsActive = false;
            await db.SaveChangesAsync();
        }

        await update.Invoking(x => x).Should().ThrowAsync<InvalidOperationException>().WithMessage("*archived*");
        await create.Invoking(x => x).Should().ThrowAsync<InvalidOperationException>().WithMessage("*archived*");
        (await svc.GetAsync(id))!.TemplateId.Should().BeNull();
        (await svc.ListAllAsync()).Should().NotContain(p => p.Name == "Full pack");
    }

    [Fact]
    public async Task A_profile_saved_between_the_name_check_and_the_insert_is_reported_as_a_duplicate(/* BUG-339 */)
    {
        // The other save lands after CreateAsync's AnyAsync check but before its own insert reaches the unique index.
        var racer = new BeforeFirstSave(async () =>
        {
            await using var other = NewContext();
            other.ReportProfiles.Add(new IncidentManager.Domain.Entities.ReportProfile
                { Name = "Executive summary", CreatedBy = "admin2", CreatedAtUtc = _clock.UtcNow });
            await other.SaveChangesAsync();
        });
        var factory = new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(racer,
                new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options);

        var create = async () => await new ReportProfileService(factory, _user, _clock)
            .CreateAsync(new ReportProfileInput("Executive summary", null, true, 1, null));

        (await create.Should().ThrowAsync<InvalidOperationException>()).WithMessage("*already exists*");
        await using var db = NewContext();
        (await db.ReportProfiles.CountAsync(p => p.Name == "Executive summary")).Should().Be(1);
    }

    /// <summary>Runs another save once, in the middle of the first save made through these options.</summary>
    private sealed class BeforeFirstSave(Func<Task> during) : Microsoft.EntityFrameworkCore.Diagnostics.SaveChangesInterceptor
    {
        private bool _done;

        public override async ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int>> SavingChangesAsync(
            Microsoft.EntityFrameworkCore.Diagnostics.DbContextEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (!_done)
            {
                _done = true;
                await during();
            }
            return result;
        }
    }

    private static async Task<string> ReadWordXmlAsync(ReportService svc, Guid reportId)
    {
        var (_, stream) = await svc.OpenAsync(reportId);
        await using (stream)
        {
            using var zip = new System.IO.Compression.ZipArchive(stream, System.IO.Compression.ZipArchiveMode.Read);
            await using var docStream = zip.GetEntry("word/document.xml")!.Open();
            return await new StreamReader(docStream).ReadToEndAsync();
        }
    }


    public void Dispose()
    {
        _connection.Dispose();
        if (Directory.Exists(_reportDir)) Directory.Delete(_reportDir, recursive: true);
    }
}
