using System.Text;
using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Evidence;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-26: any file pasted or dropped on the timeline composer is stored as evidence in the entry's save, as a screenshot
/// is (WF-31); one that isn't an image is cited by the entry, so it reads "Evidence: file.csv" as a citation made later
/// does, and an image keeps the screenshot path. Everything an upload is held to is checked before a byte is stored: the
/// entry itself, the room and quota (PROD-55) and the same file already on the case (PROD-59). A file that can run is
/// kept like any other (PROD-58 zips its download). On both providers.
/// </summary>
public sealed class TimelineAttachmentTests : IDisposable
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "ic1", RoleSet = [AppRole.IncidentCommander] };
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-timeline-attach", Guid.NewGuid().ToString("N"));
    private readonly TestOptionsMonitor<EvidenceStorageOptions> _limits = new(new EvidenceStorageOptions { MinFreeSpaceGB = 0 });

    public static TheoryData<string> Providers => TestDatabase.Providers;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private string StoreRoot => Path.Combine(_dir, "store");
    private FileEvidenceStore Store() => new(Options.Create(new EvidenceStoreOptions { RootPath = StoreRoot }));

    private int StoredFiles() => Directory.Exists(StoreRoot) ? Directory.EnumerateFiles(StoreRoot, "*", SearchOption.AllDirectories).Count() : 0;

    private CaseService Cases(TestDatabase db) =>
        new(db.Factory(), _user, _clock, new CaseNumberGenerator(db.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
            evidenceStore: Store(), evidenceLimits: _limits);

    private async Task<(TestDatabase Db, CaseService Svc, Guid CaseId)> OpenAsync(string provider)
    {
        var db = TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
        var svc = Cases(db);
        var id = (await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Attach", Title = "Payroll fraud", Classification = Classification.Incident, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, DetectedAtUtc = _clock.UtcNow.AddDays(-1)
        })).Id;
        return (db, svc, id);
    }

    private static CaseService.Screenshot File(string name, string type, string content) =>
        new(name, type, Encoding.UTF8.GetBytes(content), CaseService.AttachedFromTimeline);

    private static async Task<Case> LoadAsync(TestDatabase db, Guid id)
    {
        await using var ctx = db.NewContext();
        return await ctx.Cases.AsNoTracking().AsSplitQuery().Include(c => c.TimelineEntries).Include(c => c.Evidence)
            .ThenInclude(e => e.CustodyEvents).Include(c => c.Citations).SingleAsync(c => c.Id == id);
    }

    private Task<Guid> AddAsync(CaseService svc, Guid caseId, CaseService.Screenshot? file, string text = "Exported the payroll changes") =>
        svc.AddTimelineEntryAsync(caseId, TimelineKind.Investigation, TimelineEntryType.Analysis, _clock.UtcNow.AddHours(-1),
            text, null, screenshot: file);

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_file_that_isnt_an_image_is_stored_and_cited_in_the_entrys_save(string provider)
    {
        var (db, svc, id) = await OpenAsync(provider);
        using var _ = db;

        var entryId = await AddAsync(svc, id, File("payroll-changes.csv", "text/csv", "employee,old,new\n1042,acct-1,acct-9\n"));

        var c = await LoadAsync(db, id);
        var entry = c.TimelineEntries.Single(e => e.Id == entryId);
        entry.EvidenceId.Should().BeNull("a file that isn't an image isn't shown as the entry's screenshot");
        var ev = c.Evidence.Should().ContainSingle().Subject;
        ev.OriginalFileName.Should().Be("payroll-changes.csv");
        ev.ContentType.Should().Be("text/csv");
        ev.Description.Should().Be(CaseService.AttachedFromTimeline);
        ev.CollectedAtUtc.Should().BeNull("the composer records no collection details (CAP-08)");
        ev.CustodyEvents.Should().ContainSingle(x => x.Action == "Uploaded");
        c.Citations.Should().ContainSingle(x => x.TimelineEntryId == entryId && x.EvidenceId == ev.Id);
        StoredFiles().Should().Be(1);

        await using var ctx = db.NewContext();
        var chain = await ctx.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_image_keeps_the_screenshot_path_and_an_event_step_cites_a_file_too(string provider)
    {
        var (db, svc, id) = await OpenAsync(provider);
        using var _ = db;

        var shotEntry = await AddAsync(svc, id, new CaseService.Screenshot("pasted.png", "image/png", [0x89, 0x50, 0x4E, 0x47, 1, 2, 3]));
        var step = await svc.AddEventStepAsync(id, _clock.UtcNow.AddHours(-2), [MitreTactic.Exfiltration], null, null, null,
            "Copied the export off the share", null, screenshot: File("share-audit.log", "text/plain", "4663 read payroll.xlsx"));

        var c = await LoadAsync(db, id);
        var shot = c.Evidence.Single(e => e.OriginalFileName == "pasted.png");
        c.TimelineEntries.Single(e => e.Id == shotEntry).EvidenceId.Should().Be(shot.Id);
        shot.Description.Should().Be("Pasted into the timeline");
        c.Citations.Should().NotContain(x => x.TimelineEntryId == shotEntry, "a screenshot is the entry's picture, not a citation");
        var log = c.Evidence.Single(e => e.OriginalFileName == "share-audit.log");
        c.TimelineEntries.Single(e => e.Id == step).EvidenceId.Should().BeNull();
        c.Citations.Should().ContainSingle(x => x.TimelineEntryId == step && x.EvidenceId == log.Id);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_file_that_can_run_is_kept_as_evidence_and_its_download_is_zipped(string provider)
    {
        var (db, svc, id) = await OpenAsync(provider);
        using var _ = db;
        var program = new CaseService.Screenshot("invoice.pdf.exe", "application/x-msdownload", [(byte)'M', (byte)'Z', 0x90, 0, 3, 0],
            CaseService.AttachedFromTimeline);

        var entryId = await AddAsync(svc, id, program, "The attachment the clerk opened");

        var c = await LoadAsync(db, id);
        var ev = c.Evidence.Should().ContainSingle().Subject;
        c.Citations.Should().ContainSingle(x => x.TimelineEntryId == entryId && x.EvidenceId == ev.Id);
        EvidenceRisk.ZipFirst(SafeDownloadMode.RiskyTypes, ev.OriginalFileName, ev.ContentType).Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task What_an_upload_is_refused_for_is_refused_before_a_byte_is_stored(string provider)
    {
        var (db, svc, id) = await OpenAsync(provider);
        using var _ = db;
        // PROD-59: the same file already on the case, uploaded on the Evidence tab.
        var evidence = new EvidenceService(db.Factory(), Store(), _user, _clock, new NoOpAuditWriter(), _limits);
        await using (var s = new MemoryStream(Encoding.UTF8.GetBytes("employee,old,new\n")))
            await evidence.UploadAsync(id, "payroll.csv", "text/csv", s, null);
        var before = StoredFiles();

        var duplicate = () => AddAsync(svc, id, File("copy-of-payroll.csv", "text/csv", "employee,old,new\n"));
        (await duplicate.Should().ThrowAsync<ArgumentException>()).WithMessage("*already evidence in this case, as \"payroll.csv\"*");

        // WF-31: an entry refused for its own reasons stores nothing either.
        var empty = () => AddAsync(svc, id, File("notes.txt", "text/plain", "something new"), text: "  ");
        await empty.Should().ThrowAsync<ArgumentException>();

        // PROD-55: past the largest file allowed.
        _limits.CurrentValue.MaxUploadMB = 1;
        var big = () => AddAsync(svc, id, new CaseService.Screenshot("dump.bin", "application/octet-stream", new byte[1024 * 1024 + 1]));
        (await big.Should().ThrowAsync<ArgumentException>()).WithMessage("*largest file CaseBook takes*");

        var name = () => AddAsync(svc, id, File(new string('n', EvidenceService.MaxFileNameLength + 1) + ".txt", "text/plain", "x"));
        await name.Should().ThrowAsync<ArgumentException>();

        StoredFiles().Should().Be(before, "nothing refused reaches the store");
        var c = await LoadAsync(db, id);
        c.Evidence.Should().ContainSingle("only the Evidence tab's upload");
        c.Citations.Should().BeEmpty();
        c.TimelineEntries.Should().NotContain(e => e.Kind == TimelineKind.Investigation && e.Type == TimelineEntryType.Analysis);
    }
}
