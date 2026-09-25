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
            new IncidentManager.Infrastructure.Severities.ConfigurationSeverityLabels(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()),
            diagrams: new IncidentManager.Infrastructure.Reporting.SkiaReportDiagrams());   // PROD-46: real pictures
    }

    [Fact]
    public async Task The_report_shows_people_by_name_and_labels_in_words()
    {
        _user.RoleSet = [AppRole.IncidentCommander];
        Guid caseId;
        await using (var db = NewContext())
        {
            await DevDataSeeder.SeedAsync(db, _clock);
            var cases = new IncidentManager.Application.Cases.CaseService(NewFactory(), _user, _clock,
                new CaseNumberGenerator(db), new IncidentManager.Application.Cases.CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());
            caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
            await cases.AddEventStepAsync(caseId, _clock.UtcNow, new[] { MitreTactic.CommandAndControl },
                null, null, null, "Beacon to the C2 host", "SIEM");
            await cases.AddNoteAsync(caseId, "Named-author note");
        }

        await using (var db = NewContext())
        {
            var store = new FileReportStore(Options.Create(new ReportOutputOptions { RootPath = _reportDir }));
            var branding = new FileReportBrandingStore(Options.Create(new ReportBrandingOptions { RootPath = Path.Combine(_reportDir, "branding") }));
            var svc = new ReportService(NewFactory(), new ReportGenerator(), store, _hasher, _user, _clock,
                new IncidentManager.Application.Content.MarkdownService(), _reporting, branding, new NamingUserDirectory(),
                new IncidentManager.Infrastructure.Severities.ConfigurationSeverityLabels(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()));
            var m = await svc.BuildPreviewModelAsync(caseId, null);

            m.Notes.Should().Contain(n => n.Author == $"Name of {_user.UserId}");
            m.ClassificationHistory.Should().NotBeEmpty();
            m.ClassificationHistory.Should().OnlyContain(h => h.By.StartsWith("Name of "));
            m.ClassificationHistory.SelectMany(h => new[] { h.From, h.To }).Should().NotContain(new[] { "AdverseEvent", "ComplexEvent" });
            m.AttackChain.Should().Contain(s => s.Tactics.Contains("Command And Control") || s.Tactics.Contains("Command and Control"));
            m.Assignments.Select(a => a.Role).Should().NotContain("IncidentCommander");
        }
    }

    /// <summary>Resolves every id to "Name of {id}", so a test can tell a resolved name from a raw id.</summary>
    private sealed class NamingUserDirectory : IncidentManager.Application.Abstractions.IUserDirectory
    {
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<IncidentManager.Application.Abstractions.UserSummary> All() => Array.Empty<IncidentManager.Application.Abstractions.UserSummary>();
        public IncidentManager.Application.Abstractions.UserSummary? Resolve(string userId) => null;
        public string DisplayFor(string? userId) => userId is null ? "—" : $"Name of {userId}";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
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
            var report = await svc.GenerateAsync(caseId);

            var (_, stream) = await svc.OpenAsync(report.Id);
            string documentXml;
            await using (stream)
            {
                using var zip = new System.IO.Compression.ZipArchive(stream, System.IO.Compression.ZipArchiveMode.Read);
                await using var docStream = zip.GetEntry("word/document.xml")!.Open();
                documentXml = await new StreamReader(docStream).ReadToEndAsync();
            }

            documentXml.Should().Contain("Event Timeline");
            documentXml.Should().Contain("Lateral Movement").And.NotContain("LateralMovement");
            // PROD-46: the attack chain and entity graph are embedded as pictures with alt text.
            documentXml.Should().Contain("descr=\"Attack chain").And.Contain("descr=\"Entity relationship graph");
            documentXml.Should().Contain("Pivoted to the finance account jdoe");
            documentXml.Should().Contain("T1021");
        }
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
            var report = await svc.GenerateAsync(caseId);
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
    public async Task A_generated_report_is_a_draft_until_approved_and_its_stored_hash_matches_the_record()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewReportService(db);
        var caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;

        var report = await svc.GenerateAsync(caseId);
        report.IsFinal.Should().BeFalse("generation now produces a draft (E-15)");

        // An analyst can generate but not approve: the service asserts ApproveReports, not just the UI.
        await Assert.ThrowsAsync<IncidentManager.Application.Security.ForbiddenException>(() => svc.ApproveAsync(report.Id));

        _user.RoleSet = [AppRole.IncidentCommander];
        var approved = await svc.ApproveAsync(report.Id);
        approved.IsFinal.Should().BeTrue();
        approved.ApprovedBy.Should().Be(_user.UserId);
        report.ContentSha256.Should().HaveLength(64);

        // The file on disk hashes to exactly what we recorded.
        (await svc.VerifyFileAsync(report.Id)).Should().BeTrue();

        report.Format.Should().Be(ReportFormat.Word, "reports are Word only");
    }

    [Fact]
    public async Task Generated_word_document_is_a_docx_package()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewReportService(db);
        var caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-02_Vendor_SaaS_Breach")).Id;

        var report = await svc.GenerateAsync(caseId);

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
        var report = await svc.GenerateAsync(theCase.Id);
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
    public async Task Generating_a_report_enforces_need_to_know_and_edit_permission()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewReportService(db);
        var theCase = await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave");
        theCase.IsRestricted = true;
        await db.SaveChangesAsync();

        // An unrelated analyst can't generate (and so read) a restricted case's report by GUID.
        _user.UserId = "outsider";
        _user.RoleSet = [AppRole.Analyst];
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => svc.GenerateAsync(theCase.Id));
        ex.Message.Should().Be("Case not found.");

        // A manager sees every case but holds no EditCases, so generation is refused outright.
        _user.RoleSet = [AppRole.Manager];
        await Assert.ThrowsAsync<IncidentManager.Application.Security.ForbiddenException>(
            () => svc.GenerateAsync(theCase.Id));
        (await db.Reports.CountAsync()).Should().Be(0);
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
        model.NotificationTriggersSummary.Should().Be("NY: Social Security number; US: Social Security number, Payment card");
    }

    [Fact]
    public async Task A_third_party_case_report_suppresses_the_attack_chain_and_keeps_the_disclosure_timeline(/* E-32 */)
    {
        await using var db = NewContext();
        _user.UserId = "ic";
        _user.RoleSet = [AppRole.Manager];

        var c = Case.Open(2026, 1, "Vendor", "Vendor disclosed a data breach", Classification.Breach,
            Severity.High, CaseOrigin.ThirdParty, "ic", _clock.UtcNow);
        // A vendor-disclosure milestone: no ATT&CK tactics / actor→target, stage carried in Type.
        c.AddEventStep(_clock.UtcNow.AddHours(1), Array.Empty<MitreTactic>(), null, null, null,
            "Vendor confirmed our records were exposed", "Acme SaaS", "ic", _clock.UtcNow,
            type: TimelineEntryType.Analysis);
        db.Cases.Add(c);
        await db.SaveChangesAsync();

        var model = await NewReportService(db).BuildPreviewModelAsync(c.Id, null);

        // No adversary kill-chain for a third-party case…
        model.AttackChain.Should().BeEmpty();
        // …but the disclosure milestone still appears on the event timeline.
        model.EventTimeline.Should().ContainSingle()
            .Which.Description.Should().Be("Vendor confirmed our records were exposed");
    }

    [Fact]
    public async Task A_word_report_can_be_approved_as_the_final_and_its_file_verifies()
    {
        // Reports are Word only, so a Word draft is what gets approved as the locked final. The stored file and
        // its SHA-256 are the record.
        _user.RoleSet = [AppRole.IncidentCommander];
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewReportService(db);
        var caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-02_Vendor_SaaS_Breach")).Id;
        var draft = await svc.GenerateAsync(caseId);

        var final = await svc.ApproveAsync(draft.Id);
        final.IsFinal.Should().BeTrue();
        final.ApprovedBy.Should().Be(_user.UserId);
        (await svc.VerifyFileAsync(final.Id)).Should().BeTrue();
        await svc.Invoking(s => s.ApproveAsync(draft.Id)).Should().ThrowAsync<InvalidOperationException>().WithMessage("*already*");
    }

    [Fact]
    public async Task Approving_an_already_final_report_is_rejected()
    {
        _user.RoleSet = [AppRole.IncidentCommander];
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewReportService(db);
        var caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
        var draft = await svc.GenerateAsync(caseId);
        await svc.ApproveAsync(draft.Id);

        var act = () => svc.ApproveAsync(draft.Id);
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*already*");
    }

    [Fact]
    public async Task Separation_of_duties_blocks_the_generator_but_a_different_user_can_approve()
    {
        _reporting.CurrentValue = new ReportingOptions { RequireSeparateApprover = true };
        _user.RoleSet = [AppRole.Manager, AppRole.IncidentCommander]; // need-to-know across all cases + approve
        _user.UserId = "maker";

        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewReportService(db);
        var caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
        var draft = await svc.GenerateAsync(caseId);

        var selfApprove = () => svc.ApproveAsync(draft.Id);
        await selfApprove.Should().ThrowAsync<InvalidOperationException>().WithMessage("*Two-person*");

        _user.UserId = "checker";
        var approved = await svc.ApproveAsync(draft.Id);
        approved.IsFinal.Should().BeTrue();
        approved.ApprovedBy.Should().Be("checker");
    }

    [Fact]
    public async Task Report_lists_indicators_of_compromise_and_carries_the_chosen_TLP_marking()
    {
        // PROD-45: malicious/suspicious entities get their own section; the TLP marking prints in the header and
        // footer and is recorded on the stored report; a per-indicator marking shows in the IOC table.
        _user.RoleSet = [AppRole.IncidentCommander];
        Guid caseId;
        await using (var db = NewContext())
        {
            await DevDataSeeder.SeedAsync(db, _clock);
            var cases = new IncidentManager.Application.Cases.CaseService(NewFactory(), _user, _clock,
                new CaseNumberGenerator(db), new IncidentManager.Application.Cases.CreateCaseValidator(), new NoOpCaseNotifications(),
                new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());
            caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
            var ioc = await cases.AddEntityAsync(caseId, EntityType.Domain, "evil-cdn.test", null, EntityDisposition.Malicious, "C2 domain", null);
            await cases.AddEntityAsync(caseId, EntityType.Host, "FIN-WKS-99", null, EntityDisposition.Compromised, null, null);
            await cases.SetEntityTlpAsync(caseId, ioc, TlpLevel.Red);
        }

        await using (var db = NewContext())
        {
            var svc = NewReportService(db);

            var model = await svc.BuildPreviewModelAsync(caseId, null);
            model.Tlp.Should().Be(TlpLevel.Amber, "AMBER is the default marking");
            model.Iocs.Should().Contain(i => i.Value == "evil-cdn[.]test" && i.Tlp == "TLP:RED");
            model.Iocs.Should().NotContain(i => i.Value == "FIN-WKS-99", "a compromised host is a victim, not an indicator");

            var report = await svc.GenerateAsync(caseId, TlpLevel.Green);
            report.Tlp.Should().Be(TlpLevel.Green);

            var (_, stream) = await svc.OpenAsync(report.Id);
            string documentXml, headerXml, footerXml;
            await using (stream)
            {
                using var zip = new System.IO.Compression.ZipArchive(stream, System.IO.Compression.ZipArchiveMode.Read);
                async Task<string> Read(Func<string, bool> name) =>
                    await new StreamReader(zip.Entries.First(e => name(e.FullName)).Open()).ReadToEndAsync();
                documentXml = await Read(n => n == "word/document.xml");
                headerXml = await Read(n => n.StartsWith("word/header"));
                footerXml = await Read(n => n.StartsWith("word/footer"));
            }

            documentXml.Should().Contain("Indicators of Compromise").And.Contain("evil-cdn[.]test").And.Contain("Sharing: TLP:GREEN");
            headerXml.Should().Contain("TLP:GREEN");
            footerXml.Should().Contain("TLP:GREEN");

            // A different marking is recorded on the report generated with it.
            var amber = await svc.GenerateAsync(caseId, TlpLevel.AmberStrict);
            amber.Tlp.Should().Be(TlpLevel.AmberStrict);
        }
    }

    [Fact]
    public async Task Word_reports_use_the_profile_default_template_or_the_one_picked_and_record_which()
    {
        // PROD-47: the template library. Upload (checked), set a profile default, generate, override, preview.
        _user.RoleSet = [AppRole.SysAdmin];
        var engine = new WordTemplateEngine();
        var templateStore = new FileReportTemplateStore(Options.Create(new ReportTemplateOptions { RootPath = Path.Combine(_reportDir, "templates") }),
            Options.Create(new ReportBrandingOptions()));
        Guid caseId, profileId, houseId, boardId;
        await using (var db = NewContext())
        {
            await DevDataSeeder.SeedAsync(db, _clock);
            caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
            var templates = new IncidentManager.Application.Admin.ReportTemplateService(NewFactory(), _user, _clock, engine, templateStore);

            (await templates.UploadAsync("Broken", "bad.docx", "not a docx"u8.ToArray())).Check.Ok.Should().BeFalse();
            await templates.Invoking(t => t.UploadAsync("Macro", "macro.docm", engine.Starter())).Should().ThrowAsync<ArgumentException>();

            var house = await templates.UploadAsync("House style", "house-style.docx", engine.Starter());
            house.Check.Ok.Should().BeTrue();
            houseId = house.Id!.Value;
            boardId = (await templates.UploadAsync("Board summary", "board.docx", engine.Starter())).Id!.Value;
            await templates.Invoking(t => t.UploadAsync("house STYLE", "dup.docx", engine.Starter()))
                .Should().ThrowAsync<InvalidOperationException>("names are unique, ignoring case");

            var profiles = new IncidentManager.Application.Admin.ReportProfileService(NewFactory(), _user, _clock);
            profileId = await profiles.CreateAsync(new IncidentManager.Application.Admin.ReportProfileInput("House", null, true, 9, null, houseId));
            (await profiles.GetAsync(profileId))!.TemplateName.Should().Be("House style");

            // A profile's default can't be archived or deleted out from under it.
            await templates.Invoking(t => t.DeleteAsync(houseId)).Should().ThrowAsync<InvalidOperationException>().WithMessage("*House*");
            await templates.Invoking(t => t.UpdateAsync(houseId, "House style", isActive: false)).Should().ThrowAsync<InvalidOperationException>();
            (await templates.ListAllAsync()).Single(t => t.Id == houseId).DefaultFor.Should().Equal("House");

            var cases = new IncidentManager.Application.Cases.CaseService(NewFactory(), _user, _clock,
                new CaseNumberGenerator(db), new IncidentManager.Application.Cases.CreateCaseValidator(), new NoOpCaseNotifications(),
                new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());
            await cases.SetReportProfileAsync(caseId, profileId);
        }

        await using (var db = NewContext())
        {
            var store = new FileReportStore(Options.Create(new ReportOutputOptions { RootPath = _reportDir }));
            var branding = new FileReportBrandingStore(Options.Create(new ReportBrandingOptions { RootPath = Path.Combine(_reportDir, "branding") }));
            var svc = new ReportService(NewFactory(), new ReportGenerator(), store, _hasher, _user, _clock,
                new IncidentManager.Application.Content.MarkdownService(), _reporting, branding, new StubUserDirectory(),
                new IncidentManager.Infrastructure.Severities.ConfigurationSeverityLabels(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()),
                diagrams: new SkiaReportDiagrams(), templates: engine, templateStore: templateStore);

            async Task<string> BodyOf(Guid reportId)
            {
                var (_, stream) = await svc.OpenAsync(reportId);
                using var ms = new MemoryStream();
                await using (stream) await stream.CopyToAsync(ms);
                ms.Position = 0;
                using var doc = DocumentFormat.OpenXml.Packaging.WordprocessingDocument.Open(ms, false);
                new DocumentFormat.OpenXml.Validation.OpenXmlValidator().Validate(doc).Should().BeEmpty("Word opens it without repair");
                return doc.MainDocumentPart!.Document.Body!.InnerText;
            }

            // Profile default.
            var word = await svc.GenerateAsync(caseId);
            word.TemplateName.Should().Be("House style");
            word.TemplateSha256.Should().HaveLength(64);
            var body = await BodyOf(word.Id);
            body.Should().Contain("Business impact", "the template's own headings print")
                .And.NotContain("Systems Reviewed", "not the built-in layout")
                .And.Contain("2026-01_Phishing_Wave").And.Contain("203[.]0[.]113[.]66").And.NotContain("{{");

            // Another template picked for this report, then the built-in layout.
            (await svc.GenerateAsync(caseId, template: boardId)).TemplateName.Should().Be("Board summary");
            var builtIn = await svc.GenerateAsync(caseId, template: Guid.Empty);
            builtIn.TemplateName.Should().BeNull();
            (await BodyOf(builtIn.Id)).Should().Contain("Systems Reviewed");


            // Preview: filled and marked, but not stored.
            var before = await db.Reports.CountAsync(r => r.CaseId == caseId);
            var (fileName, bytes, caseNumber) = await svc.PreviewTemplateAsync(boardId, caseId);
            fileName.Should().StartWith("PREVIEW_Board-summary_");
            caseNumber.Should().Be("2026-01_Phishing_Wave");
            using (var ms = new MemoryStream(bytes))
            using (var doc = DocumentFormat.OpenXml.Packaging.WordprocessingDocument.Open(ms, false))
            {
                var text = doc.MainDocumentPart!.Document.Body!.InnerText;
                text.Should().StartWith("PREVIEW of template").And.Contain("2026-01_Phishing_Wave").And.NotContain("{{");
                new DocumentFormat.OpenXml.Validation.OpenXmlValidator().Validate(doc).Should().BeEmpty();
            }
            (await db.Reports.CountAsync(r => r.CaseId == caseId)).Should().Be(before, "a preview is never stored as a report");

            // Only admins preview.
            _user.RoleSet = [AppRole.Analyst];
            await svc.Invoking(s => s.PreviewTemplateAsync(boardId, caseId)).Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();
        }
    }

    public void Dispose()
    {
        _connection.Dispose();
        try { if (Directory.Exists(_reportDir)) Directory.Delete(_reportDir, recursive: true); } catch { /* best effort */ }
    }
}
