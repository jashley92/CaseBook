using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Entities;
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

public sealed class ReportingIntegrationTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();
    private readonly string _reportDir;

    public ReportingIntegrationTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _reportDir = Path.Combine(Path.GetTempPath(), "im-report-tests", Guid.NewGuid().ToString("N"));
    }

    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options);

    private readonly TestOptionsMonitor<ReportingOptions> _reporting = new(new ReportingOptions());

    private ReportService NewReportService(AppDbContext db)
    {
        var store = new FileReportStore(Options.Create(new ReportOutputOptions { RootPath = _reportDir }));
        var branding = new FileReportBrandingStore(Options.Create(new ReportBrandingOptions { RootPath = Path.Combine(_reportDir, "branding") }));
        return new ReportService(NewFactory(), new ReportGenerator(), store, _hasher, _user, _clock,
            new IncidentManager.Application.Content.MarkdownService(), _reporting, branding, new StubUserDirectory(),
            new IncidentManager.Infrastructure.Severities.ConfigurationSeverityLabels(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()));
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

    [Fact]
    public async Task Word_report_contains_the_attack_chain_from_event_steps()
    {
        _user.RoleSet = [AppRole.IncidentCommander];
        Guid caseId;
        await using (var db = NewContext())
        {
            await DevDataSeeder.SeedAsync(db, _clock);
            var cases = new IncidentManager.Application.Cases.CaseService(NewFactory(), _user, _clock,
                new CaseNumberGenerator(db), new IncidentManager.Application.Cases.CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());
            caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;

            var actor = await cases.AddEntityAsync(caseId, EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Malicious, null, null);
            var target = await cases.AddEntityAsync(caseId, EntityType.Account, "jdoe", "John Doe", EntityDisposition.Benign, null, null);
            await cases.AddEventStepAsync(caseId, _clock.UtcNow, new[] { MitreTactic.LateralMovement },
                "T1021", actor, target, "Pivoted to the finance account jdoe", "SIEM");
        }

        await using (var db = NewContext())
        {
            var svc = NewReportService(db);
            var report = await svc.GenerateAsync(caseId, ReportFormat.Word);

            var (_, stream) = await svc.OpenAsync(report.Id);
            string documentXml;
            await using (stream)
            {
                using var zip = new System.IO.Compression.ZipArchive(stream, System.IO.Compression.ZipArchiveMode.Read);
                await using var docStream = zip.GetEntry("word/document.xml")!.Open();
                documentXml = await new StreamReader(docStream).ReadToEndAsync();
            }

            documentXml.Should().Contain("Event Timeline");
            documentXml.Should().Contain("LateralMovement");
            documentXml.Should().Contain("Pivoted to the finance account jdoe");
            documentXml.Should().Contain("T1021");
        }
    }

    private sealed class NoOpCaseNotifications : IncidentManager.Application.Abstractions.ICaseNotifications
    {
        public System.Threading.Tasks.Task OnAssignedAsync(IncidentManager.Domain.Entities.Case c, string assigneeUserId, string assigneeDisplayName, IncidentManager.Domain.Enums.CaseAssignmentRole role, string assignedByUserId, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public System.Threading.Tasks.Task OnActionItemsOverdueAsync(System.Collections.Generic.IReadOnlyList<IncidentManager.Application.Abstractions.OverdueActionItem> items, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public Task OnReclassifiedAsync(IncidentManager.Domain.Entities.Case c, Classification? from, Classification to, CancellationToken ct = default)
            => Task.CompletedTask;
    }

    [Fact]
    public async Task Investigation_entries_with_equal_timestamp_keep_submission_order()
    {
        // Regression: the datetime-local picker is minute-precision, so several investigation entries can
        // share the exact same OccurredAtUtc. Ordering must then fall back to submission order (CreatedAtUtc),
        // not an arbitrary row order. Same occurred-at for all three; advance the clock between adds so each
        // gets a distinct CreatedAtUtc.
        _user.RoleSet = [AppRole.IncidentCommander];
        var occurred = new DateTimeOffset(2026, 8, 8, 9, 30, 0, TimeSpan.Zero);
        Guid caseId;
        await using (var db = NewContext())
        {
            await DevDataSeeder.SeedAsync(db, _clock);
            var cases = new IncidentManager.Application.Cases.CaseService(NewFactory(), _user, _clock,
                new CaseNumberGenerator(db), new IncidentManager.Application.Cases.CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());
            caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;

            await cases.AddTimelineEntryAsync(caseId, TimelineKind.Investigation, TimelineEntryType.Analysis, occurred, "AlphaNote", null);
            _clock.UtcNow = _clock.UtcNow.AddSeconds(5);
            await cases.AddTimelineEntryAsync(caseId, TimelineKind.Investigation, TimelineEntryType.Analysis, occurred, "BravoNote", null);
            _clock.UtcNow = _clock.UtcNow.AddSeconds(5);
            await cases.AddTimelineEntryAsync(caseId, TimelineKind.Investigation, TimelineEntryType.Analysis, occurred, "CharlieNote", null);
        }

        await using (var db = NewContext())
        {
            var svc = NewReportService(db);
            var report = await svc.GenerateAsync(caseId, ReportFormat.Word);
            var (_, stream) = await svc.OpenAsync(report.Id);
            string xml;
            await using (stream)
            {
                using var zip = new System.IO.Compression.ZipArchive(stream, System.IO.Compression.ZipArchiveMode.Read);
                await using var docStream = zip.GetEntry("word/document.xml")!.Open();
                xml = await new StreamReader(docStream).ReadToEndAsync();
            }

            xml.IndexOf("AlphaNote", StringComparison.Ordinal).Should().BeLessThan(xml.IndexOf("BravoNote", StringComparison.Ordinal));
            xml.IndexOf("BravoNote", StringComparison.Ordinal).Should().BeLessThan(xml.IndexOf("CharlieNote", StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task Generated_pdf_is_a_pdf_and_its_stored_hash_matches_the_record()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewReportService(db);
        var caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;

        var report = await svc.GenerateAsync(caseId, ReportFormat.Pdf);
        report.IsFinal.Should().BeFalse("generation now produces a draft (E-15)");

        var approved = await svc.ApproveAsync(report.Id);
        approved.IsFinal.Should().BeTrue();
        approved.ApprovedBy.Should().Be(_user.UserId);
        report.ContentSha256.Should().HaveLength(64);

        // The file on disk hashes to exactly what we recorded.
        (await svc.VerifyFileAsync(report.Id)).Should().BeTrue();

        // And it's genuinely a PDF.
        var (_, stream) = await svc.OpenAsync(report.Id);
        await using (stream)
        {
            var header = new byte[5];
            _ = await stream.ReadAsync(header);
            Encoding.ASCII.GetString(header, 0, 4).Should().Be("%PDF");
        }
    }

    [Fact]
    public async Task Generated_word_document_is_a_docx_package()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewReportService(db);
        var caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-02_Vendor_SaaS_Breach")).Id;

        var report = await svc.GenerateAsync(caseId, ReportFormat.Word);

        report.IsFinal.Should().BeFalse();
        (await svc.VerifyFileAsync(report.Id)).Should().BeTrue();

        var (_, stream) = await svc.OpenAsync(report.Id);
        await using (stream)
        {
            var header = new byte[2];
            _ = await stream.ReadAsync(header);
            // OOXML is a ZIP package — starts with "PK".
            Encoding.ASCII.GetString(header).Should().Be("PK");
        }
    }

    [Fact]
    public async Task Opening_a_report_on_a_restricted_case_is_denied_for_an_unrelated_user()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewReportService(db);
        var theCase = await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave");

        // Generate a report while the current user can see the case, then lock the case down.
        var report = await svc.GenerateAsync(theCase.Id, ReportFormat.Pdf);
        theCase.IsRestricted = true;
        await db.SaveChangesAsync();

        // An unrelated analyst (not the IC, not assigned) must not reach the report by GUID.
        _user.UserId = "outsider";
        _user.RoleSet = [AppRole.Analyst];
        await Assert.ThrowsAsync<InvalidOperationException>(() => svc.OpenAsync(report.Id));

        // A manager has need-to-know across all cases and can still open it.
        _user.RoleSet = [AppRole.Manager];
        var (opened, stream) = await svc.OpenAsync(report.Id);
        await stream.DisposeAsync();
        opened.Id.Should().Be(report.Id);
    }

    [Fact]
    public async Task The_report_groups_data_elements_by_the_jurisdiction_they_trigger_notification_in(/* X-03 slice C */)
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedDataElementsAsync(db, _clock);

        // Give two elements a notification jurisdiction, then record them on a case.
        var ssn = await db.DataElements.FirstAsync(e => e.Key == "SocialSecurityNumber");
        var pay = await db.DataElements.FirstAsync(e => e.Key == "PaymentCard");
        ssn.NotificationJurisdictions = "US,NY";
        pay.NotificationJurisdictions = "US";

        _user.UserId = "ic";
        _user.RoleSet = [AppRole.Manager];
        var c = Case.Open(2026, 1, "Rep", "Report test", Classification.Breach,
            Severity.High, CaseOrigin.InternalDetection, "ic", _clock.UtcNow);
        c.SetImpactAssessment(1000, new[] { ssn.Key, pay.Key }, "NY", "ic", _clock.UtcNow);
        db.Cases.Add(c);
        await db.SaveChangesAsync();

        var model = await NewReportService(db).BuildPreviewModelAsync(c.Id, null);

        model.DataElementsSummary.Should().Contain("Social Security number").And.Contain("Payment card");
        // Grouped by jurisdiction (ordinal), elements in reference display order within each group.
        model.NotificationTriggersSummary.Should().Be("NY — Social Security number; US — Social Security number, Payment card");
    }

    [Fact]
    public async Task Approving_a_word_draft_is_rejected_only_a_pdf_can_be_the_final()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewReportService(db);
        var caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-02_Vendor_SaaS_Breach")).Id;
        var draft = await svc.GenerateAsync(caseId, ReportFormat.Word);

        var act = () => svc.ApproveAsync(draft.Id);
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*PDF*");
    }

    [Fact]
    public async Task Approving_an_already_final_report_is_rejected()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewReportService(db);
        var caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
        var draft = await svc.GenerateAsync(caseId, ReportFormat.Pdf);
        await svc.ApproveAsync(draft.Id);

        var act = () => svc.ApproveAsync(draft.Id);
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*already*");
    }

    [Fact]
    public async Task Separation_of_duties_blocks_the_generator_but_a_different_user_can_approve()
    {
        _reporting.CurrentValue = new ReportingOptions { RequireSeparateApprover = true };
        _user.RoleSet = [AppRole.Manager]; // need-to-know across all cases
        _user.UserId = "maker";

        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewReportService(db);
        var caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
        var draft = await svc.GenerateAsync(caseId, ReportFormat.Pdf);

        var selfApprove = () => svc.ApproveAsync(draft.Id);
        await selfApprove.Should().ThrowAsync<InvalidOperationException>().WithMessage("*Two-person*");

        _user.UserId = "checker";
        var approved = await svc.ApproveAsync(draft.Id);
        approved.IsFinal.Should().BeTrue();
        approved.ApprovedBy.Should().Be("checker");
    }

    public void Dispose()
    {
        _connection.Dispose();
        try { if (Directory.Exists(_reportDir)) Directory.Delete(_reportDir, recursive: true); } catch { /* best effort */ }
    }
}
