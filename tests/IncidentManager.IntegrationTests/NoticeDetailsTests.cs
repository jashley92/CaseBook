using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Common;
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
/// CAP-07: how a regulator was notified (method, reference, who gave it, the evidence file holding it), recorded with a
/// notice or edited on it later without moving its time. A notice without them keeps its hash; the file must be one on the
/// same visible case; a stale edit is refused; the details reach the milestone, the report, its template fields and the
/// legal register. Runs on SQLite always and on SQL Server when <c>CASEBOOK_TEST_SQL</c> is set.
/// </summary>
public sealed class NoticeDetailsTests : IDisposable
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 15, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "ic1", RoleSet = [AppRole.SysAdmin] };
    private readonly string _reportDir = Path.Combine(Path.GetTempPath(), "im-notice-tests", Guid.NewGuid().ToString("N"));

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));

    private CaseService NewService(TestDatabase database, TestCurrentUser? user = null) =>
        new(database.Factory(), user ?? _user, _clock, new CaseNumberGenerator(database.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private async Task<Guid> NewCaseAsync(CaseService svc, string name = "Notice") =>
        (await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = name, Title = $"{name} breach", Classification = Classification.Breach, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, DetectedAtUtc = _clock.UtcNow.AddDays(-2),
        })).Id;

    private async Task<Guid> AddEvidenceAsync(TestDatabase database, Guid caseId, string name)
    {
        await using var db = database.NewContext();
        var ev = new Evidence
        {
            CaseId = caseId, OriginalFileName = name, ContentType = "application/pdf", SizeBytes = 10, Sha256 = new string('a', 64),
            StoragePath = Guid.NewGuid().ToString("N"), CreatedBy = "ic1", CreatedAtUtc = _clock.UtcNow,
        };
        db.Evidence.Add(ev);
        await db.SaveChangesAsync();
        return ev.Id;
    }

    private static async Task<JurisdictionNotice> NoticeAsync(TestDatabase database, Guid caseId, string code = "NY")
    {
        await using var db = database.NewContext();
        return await db.JurisdictionNotices.AsNoTracking().SingleAsync(n => n.CaseId == caseId && n.Jurisdiction == code);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task How_a_regulator_was_notified_round_trips_and_is_edited_without_moving_the_time(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await NewCaseAsync(svc);
        var file = await AddEvidenceAsync(database, id, "nydfs-ack.pdf");
        var at = _clock.UtcNow.AddHours(-5);

        await svc.RecordNoticeAsync(id, "ny", at, Shown.Of<DateTimeOffset?>(null),
            new NoticeDetails(NoticeMethod.Portal, "  NYDFS-2026-114 ", "Pat Lee (outside counsel)", file));

        var n = await NoticeAsync(database, id);
        (n.Method, n.Reference, n.NotifiedBy, n.EvidenceId).Should().Be((NoticeMethod.Portal, "NYDFS-2026-114", "Pat Lee (outside counsel)", file));
        n.RowHash.Should().StartWith(Canonical.V5Prefix);
        _hasher.RowHashMatches(n, n.RowHash!).Should().BeTrue();

        _clock.UtcNow = _clock.UtcNow.AddMinutes(30);
        (await svc.UpdateNoticeDetailsAsync(id, "NY", new NoticeDetails(NoticeMethod.Letter, "NYDFS-2026-115", " ", null),
            n.DetailsConcurrencyStamp())).Should().BeTrue();
        var edited = await NoticeAsync(database, id);
        (edited.Method, edited.Reference, edited.NotifiedBy, edited.EvidenceId).Should().Be((NoticeMethod.Letter, "NYDFS-2026-115", (string?)null, (Guid?)null));
        edited.NotifiedAtUtc.Should().Be(at, "editing how it was notified doesn't move when");
        edited.CreatedAtUtc.Should().Be(n.CreatedAtUtc);
        (await svc.UpdateNoticeDetailsAsync(id, "NY", new NoticeDetails(NoticeMethod.Letter, "NYDFS-2026-115"))).Should().BeFalse("nothing changed");

        // Correcting the time without details keeps them (the old call shape).
        await svc.RecordNoticeAsync(id, "NY", at.AddMinutes(-10));
        (await NoticeAsync(database, id)).Reference.Should().Be("NYDFS-2026-115");

        await using var db = database.NewContext();
        var entries = await db.AuditLog.AsNoTracking().Where(a => a.EntityType == nameof(JurisdictionNotice)).OrderBy(a => a.Sequence).ToListAsync();
        entries.Should().Contain(e => e.Action == AuditAction.Update && e.AfterJson!.Contains("NYDFS-2026-115"));
        _hasher.VerifyChain(await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_notice_without_the_details_keeps_the_hash_it_had(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await NewCaseAsync(svc);
        await svc.RecordNoticeAsync(id, "NY", _clock.UtcNow.AddHours(-1));

        var n = await NoticeAsync(database, id);
        n.HasDetails.Should().BeFalse();
        // The stored hash is the one format 4 (v1.9.0) built: only the prefix says format 5.
        n.RowHash.Should().Be(Canonical.V5Prefix + _hasher.Hash(Canonical.InFormat(4, n.BuildCanonicalContent)));
        _hasher.RowHashMatches(n, Canonical.V4Prefix + _hasher.Hash(Canonical.InFormat(4, n.BuildCanonicalContent))).Should().BeTrue();
        Canonical.Covers(4, n.BuildCanonicalContent).Should().BeTrue("a v1.9.0 hash still covers everything it holds");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_file_from_another_case_or_none_at_all_is_refused(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await NewCaseAsync(svc);
        var other = await NewCaseAsync(svc, "Other");
        var elsewhere = await AddEvidenceAsync(database, other, "other-case.pdf");

        await svc.Invoking(s => s.RecordNoticeAsync(id, "NY", _clock.UtcNow, details: new NoticeDetails(NoticeMethod.Email, EvidenceId: elsewhere)))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("Only evidence on this case*");
        await using (var db = database.NewContext())
            (await db.JurisdictionNotices.AnyAsync(n => n.CaseId == id)).Should().BeFalse("nothing is recorded when the file is refused");

        await svc.RecordNoticeAsync(id, "NY", _clock.UtcNow);
        foreach (var file in new[] { elsewhere, Guid.NewGuid() })
            await svc.Invoking(s => s.UpdateNoticeDetailsAsync(id, "NY", new NoticeDetails(EvidenceId: file)))
                .Should().ThrowAsync<InvalidOperationException>().WithMessage("Only evidence on this case*");
        (await NoticeAsync(database, id)).EvidenceId.Should().BeNull();

        // Text too long, or a method that isn't one, is refused too; a regulator with no notice has nothing to edit.
        await svc.Invoking(s => s.UpdateNoticeDetailsAsync(id, "NY", new NoticeDetails(Reference: new string('r', JurisdictionNotice.MaxReferenceLength + 1))))
            .Should().ThrowAsync<ArgumentException>();
        await svc.Invoking(s => s.UpdateNoticeDetailsAsync(id, "NY", new NoticeDetails((NoticeMethod)99)))
            .Should().ThrowAsync<ArgumentException>();
        await svc.Invoking(s => s.UpdateNoticeDetailsAsync(id, "CA", new NoticeDetails(NoticeMethod.Phone)))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("*no notice recorded*");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_restricted_case_and_its_files_are_out_of_reach_without_need_to_know(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await NewCaseAsync(svc);
        var file = await AddEvidenceAsync(database, id, "nydfs-ack.pdf");
        await svc.RecordNoticeAsync(id, "NY", _clock.UtcNow);
        await svc.SetRestrictedAsync(id, true, "Insider matter");

        var outsider = NewService(database, new TestCurrentUser { UserId = "analyst-unrelated", RoleSet = [AppRole.Analyst] });
        await outsider.Invoking(s => s.UpdateNoticeDetailsAsync(id, "NY", new NoticeDetails(NoticeMethod.Portal, "X-1", EvidenceId: file)))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("Case not found or not accessible.");
        await outsider.Invoking(s => s.RecordNoticeAsync(id, "CA", _clock.UtcNow, details: new NoticeDetails(NoticeMethod.Portal)))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("Case not found or not accessible.");

        // Their own case can't name the restricted case's file either.
        var theirs = await NewCaseAsync(outsider, "Theirs");
        await outsider.RecordNoticeAsync(theirs, "NY", _clock.UtcNow);
        await outsider.Invoking(s => s.UpdateNoticeDetailsAsync(theirs, "NY", new NoticeDetails(EvidenceId: file)))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("Only evidence on this case*");
        (await NoticeAsync(database, id)).HasDetails.Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_stale_edit_is_refused_and_a_deliberate_second_save_lands(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await NewCaseAsync(svc);
        await svc.RecordNoticeAsync(id, "NY", _clock.UtcNow);
        var opened = (await NoticeAsync(database, id)).DetailsConcurrencyStamp();

        // A colleague saves first; the page opened before it is refused, and told what's there now.
        await svc.UpdateNoticeDetailsAsync(id, "NY", new NoticeDetails(NoticeMethod.Phone, "CALL-7"), opened);
        var ex = await Assert.ThrowsAsync<StaleEditException>(() =>
            svc.UpdateNoticeDetailsAsync(id, "NY", new NoticeDetails(NoticeMethod.Email, "MAIL-9"), opened));
        ex.CurrentStamp.Should().Be((await NoticeAsync(database, id)).DetailsConcurrencyStamp());
        (await NoticeAsync(database, id)).Reference.Should().Be("CALL-7");

        (await svc.UpdateNoticeDetailsAsync(id, "NY", new NoticeDetails(NoticeMethod.Email, "MAIL-9"), ex.CurrentStamp)).Should().BeTrue();
        (await NoticeAsync(database, id)).Reference.Should().Be("MAIL-9");

        // Removed meanwhile: refused as stale, not recreated.
        var stamp = (await NoticeAsync(database, id)).DetailsConcurrencyStamp();
        await svc.RemoveNoticeAsync(id, "NY");
        await Assert.ThrowsAsync<StaleEditException>(() => svc.UpdateNoticeDetailsAsync(id, "NY", new NoticeDetails(NoticeMethod.Letter), stamp));
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_details_reach_the_milestone_the_report_its_template_fields_and_the_legal_register(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await NewCaseAsync(svc);
        var file = await AddEvidenceAsync(database, id, "nydfs-ack.pdf");
        var at = _clock.UtcNow.AddHours(-3);
        await svc.RecordNoticeAsync(id, "NY", at, details: new NoticeDetails(NoticeMethod.Portal, "NYDFS-2026-114", "Pat Lee", file));
        await svc.RecordNoticeAsync(id, "CA", at.AddHours(1));
        const string how = "By portal, reference NYDFS-2026-114, notified by Pat Lee, notice file nydfs-ack.pdf";

        // The timeline milestone "Notified NY" says how; CA's has nothing to add.
        await using (var db = database.NewContext())
        {
            var c = await db.Cases.AsNoTracking().AsSplitQuery().Include(x => x.JurisdictionNotices).Include(x => x.Evidence).SingleAsync(x => x.Id == id);
            var milestones = CaseMilestones.Project(c, new MilestoneLabels(x => "", s => "", p => "", m => ""));
            milestones.Single(m => m.Title == "Notified NY").Detail.Should().Be(how);
            milestones.Single(m => m.Title == "Notified CA").Detail.Should().BeNull();
        }

        // The report's notification summary and the notice.* template fields.
        var model = await NewReportService(database).BuildPreviewModelAsync(id, null);
        model.Notices.Select(x => x.Jurisdiction).Should().Equal("NY", "CA");
        model.BusinessImpactLines.Should().Contain($"Notice to NY: {at.UtcDateTime:yyyy-MM-dd HH:mm} UTC. {how}.")
            .And.Contain($"Notice to CA: {at.AddHours(1).UtcDateTime:yyyy-MM-dd HH:mm} UTC.");
        ReportTemplateFields.CollectionFor("notice.reference").Should().Be("notice");
        var ny = ReportTemplateFields.Items(model, "notice")[0];
        (ny("notice.jurisdiction"), ny("notice.method"), ny("notice.reference"), ny("notice.by"), ny("notice.file"))
            .Should().Be(("NY", "Portal", "NYDFS-2026-114", "Pat Lee", "nydfs-ack.pdf"));
        ny("notice.notified").Should().Be($"{at.UtcDateTime:yyyy-MM-dd HH:mm} UTC");
        ReportTemplateFields.Items(model, "notice")[1]("notice.reference").Should().BeEmpty();

        // The legal register's reference column.
        var register = new LegalRegisterService(database.Factory(), _user,
            new NotificationDeadlineService(database.Factory(), new OffSettings(), new IncidentManager.Application.Admin.NotificationRuleService(database.Factory(), _user, _clock), _clock),
            new StubUserDirectory());
        var row = (await register.BuildAsync()).Single();
        row.NoticeReferences.Should().Be("NY: NYDFS-2026-114");
        var csv = LegalRegisterService.ToCsv([row], _clock.UtcNow);
        csv.Should().Contain(",deadline_status,notice_references\r\n").And.Contain(",NY: NYDFS-2026-114\r\n");
    }

    private ReportService NewReportService(TestDatabase database) =>
        new(database.Factory(), new ReportGenerator(),
            new FileReportStore(Options.Create(new ReportOutputOptions { RootPath = _reportDir })), _hasher, _user, _clock,
            new IncidentManager.Application.Content.MarkdownService(), new TestOptionsMonitor<ReportingOptions>(new ReportingOptions()),
            new FileReportBrandingStore(Options.Create(new ReportBrandingOptions { RootPath = Path.Combine(_reportDir, "branding") })),
            new StubUserDirectory(),
            new IncidentManager.Infrastructure.Severities.ConfigurationSeverityLabels(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()));

    private sealed class OffSettings : INotificationDeadlineSettingsProvider
    {
        public NotificationDeadlineSettings Current => NotificationDeadlineSettings.Off;
    }

    private sealed class StubUserDirectory : IUserDirectory
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
        try { if (Directory.Exists(_reportDir)) Directory.Delete(_reportDir, recursive: true); }
        catch (IOException) { /* best effort */ }
    }
}
