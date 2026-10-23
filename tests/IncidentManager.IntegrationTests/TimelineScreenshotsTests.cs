using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Evidence;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-722: a timeline entry takes several screenshots. Each pasted or dropped image is its own evidence item, hashed and
/// stored as a screenshot always was, and the entry links them in order (up to ten). An edit adds more or unlinks one: an
/// Investigation entry keeps the earlier version with its screenshots, an Event step's change is in the audit trail, and
/// the evidence stays on the case (R3). Only an image on the same case links. An entry with one screenshot is stored and
/// hashed as before. On both providers.
/// </summary>
public sealed class TimelineScreenshotsTests : IDisposable
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 23, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "ic1", RoleSet = [AppRole.IncidentCommander] };
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-timeline-shots", Guid.NewGuid().ToString("N"));
    private readonly TestOptionsMonitor<EvidenceStorageOptions> _limits = new(new EvidenceStorageOptions { MinFreeSpaceGB = 0 });

    public static TheoryData<string> Providers => TestDatabase.Providers;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private string StoreRoot => Path.Combine(_dir, "store");

    private int StoredFiles() => Directory.Exists(StoreRoot) ? Directory.EnumerateFiles(StoreRoot, "*", SearchOption.AllDirectories).Count() : 0;

    private CaseService Cases(TestDatabase db) =>
        new(db.Factory(), _user, _clock, new IncidentManager.Infrastructure.Persistence.CaseNumberGenerator(db.NewContext()),
            new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(),
            new TestSlaTargets(), evidenceStore: new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = StoreRoot })),
            evidenceLimits: _limits);

    private async Task<(TestDatabase Db, CaseService Svc, Guid CaseId)> OpenAsync(string provider)
    {
        var db = TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
        var svc = Cases(db);
        return (db, svc, await NewCaseAsync(svc, "Shots"));
    }

    private async Task<Guid> NewCaseAsync(CaseService svc, string name) =>
        (await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = name, Title = name, Classification = Classification.Incident, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, DetectedAtUtc = _clock.UtcNow.AddDays(-1)
        })).Id;

    private static CaseService.Screenshot Png(int n) => new($"shot-{n}.png", "image/png", [0x89, 0x50, 0x4E, 0x47, (byte)n, (byte)(n >> 8)]);

    private static List<CaseService.Screenshot> Pngs(int from, int count) => Enumerable.Range(from, count).Select(Png).ToList();

    private Task<Guid> AddAsync(CaseService svc, Guid caseId, IReadOnlyList<CaseService.Screenshot>? shots) =>
        svc.AddTimelineEntryAsync(caseId, TimelineKind.Investigation, TimelineEntryType.Analysis, _clock.UtcNow.AddHours(-1),
            "Captured the phishing page", null, screenshots: shots);

    private static async Task<Case> LoadAsync(TestDatabase db, Guid id)
    {
        await using var ctx = db.NewContext();
        return await ctx.Cases.AsNoTracking().AsSplitQuery().Include(c => c.TimelineEntries).Include(c => c.Evidence)
            .ThenInclude(e => e.CustodyEvents).SingleAsync(c => c.Id == id);
    }

    private async Task RecordVerifiesAsync(TestDatabase database)
    {
        await using var db = database.NewContext();
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        (await RowIntegrityVerifier.VerifyAsync(db, _hasher, chain)).Should().BeNull();
    }

    private static Guid EvidenceNamed(Case c, string name) => c.Evidence.Single(e => e.OriginalFileName == name).Id;

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Each_image_is_its_own_evidence_and_the_entry_links_them_in_order(string provider)
    {
        var (db, svc, id) = await OpenAsync(provider);
        using var _ = db;
        var entryId = await AddAsync(svc, id, [Png(3), Png(1), Png(2)]);

        var c = await LoadAsync(db, id);
        var entry = c.TimelineEntries.Single(e => e.Id == entryId);
        entry.ScreenshotIds.Should().Equal(EvidenceNamed(c, "shot-3.png"), EvidenceNamed(c, "shot-1.png"), EvidenceNamed(c, "shot-2.png"));
        entry.EvidenceId.Should().Be(EvidenceNamed(c, "shot-3.png"), "the first is where a single screenshot always was");
        c.Evidence.Should().HaveCount(3).And.OnlyContain(e => e.CustodyEvents.Any(x => x.Action == "Uploaded") && e.Sha256.Length == 64);
        StoredFiles().Should().Be(3);
        await RecordVerifiesAsync(db);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_entry_takes_ten_and_more_is_refused_before_a_byte_is_stored(string provider)
    {
        var (db, svc, id) = await OpenAsync(provider);
        using var _ = db;
        var tooMany = () => AddAsync(svc, id, Pngs(1, 11));
        await tooMany.Should().ThrowAsync<ArgumentException>().WithMessage("*up to 10 screenshots*");
        StoredFiles().Should().Be(0);
        (await LoadAsync(db, id)).TimelineEntries.Should().BeEmpty();

        var entryId = await AddAsync(svc, id, Pngs(1, 10));
        var c = await LoadAsync(db, id);
        c.TimelineEntries.Single().ScreenshotIds.Should().HaveCount(10);

        // An edit that would make eleven is refused too, and stores nothing.
        var oneMore = () => svc.EditInvestigationEntryAsync(id, entryId, TimelineEntryType.Analysis, _clock.UtcNow.AddHours(-1),
            "Captured the phishing page", null, screenshots: [Png(11)]);
        await oneMore.Should().ThrowAsync<ArgumentException>();
        StoredFiles().Should().Be(10);
        (await LoadAsync(db, id)).TimelineEntries.Should().ContainSingle();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Unlinking_in_an_edit_leaves_the_earlier_version_and_keeps_the_evidence(string provider)
    {
        var (db, svc, id) = await OpenAsync(provider);
        using var _ = db;
        var v1 = await AddAsync(svc, id, Pngs(1, 3));
        var before = await LoadAsync(db, id);
        var (a, b, c3) = (EvidenceNamed(before, "shot-1.png"), EvidenceNamed(before, "shot-2.png"), EvidenceNamed(before, "shot-3.png"));

        await svc.EditInvestigationEntryAsync(id, v1, TimelineEntryType.Analysis, _clock.UtcNow.AddHours(-1),
            "Captured the phishing page", null, reason: "The second was the wrong tab", keepScreenshots: [a, c3], screenshots: [Png(4)]);

        var after = await LoadAsync(db, id);
        var old = after.TimelineEntries.Single(e => e.Id == v1);
        var now = after.TimelineEntries.Single(e => e.IsCurrent);
        old.IsCurrent.Should().BeFalse();
        old.ScreenshotIds.Should().Equal(a, b, c3);
        now.Version.Should().Be(2);
        now.ScreenshotIds.Should().Equal(a, c3, EvidenceNamed(after, "shot-4.png"));
        after.Evidence.Should().HaveCount(4).And.Contain(e => e.Id == b && !e.IsWithdrawn, "an unlinked screenshot stays evidence (R3)");
        await RecordVerifiesAsync(db);

        // Unlinking them all leaves the entry with none, and the earlier versions as they were.
        await svc.EditInvestigationEntryAsync(id, now.Id, TimelineEntryType.Analysis, _clock.UtcNow.AddHours(-1),
            "Captured the phishing page", null, keepScreenshots: []);
        var last = (await LoadAsync(db, id)).TimelineEntries.Single(e => e.IsCurrent);
        (last.EvidenceId, last.MoreEvidenceIds).Should().Be((null, null));
        await RecordVerifiesAsync(db);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_steps_unlinked_screenshot_is_an_audited_change_and_stays_on_the_case(string provider)
    {
        var (db, svc, id) = await OpenAsync(provider);
        using var _ = db;
        var stepId = await svc.AddEventStepAsync(id, _clock.UtcNow.AddHours(-2), [MitreTactic.InitialAccess], null, null, null,
            "Phishing page opened", null, screenshots: Pngs(1, 2));
        var c = await LoadAsync(db, id);
        var (a, b) = (EvidenceNamed(c, "shot-1.png"), EvidenceNamed(c, "shot-2.png"));
        c.TimelineEntries.Single().ScreenshotIds.Should().Equal(a, b);

        await svc.EditEventStepAsync(id, stepId, _clock.UtcNow.AddHours(-2), [MitreTactic.InitialAccess], null, null, null,
            "Phishing page opened", null, reason: "Not this step's", keepScreenshots: [b], screenshots: [Png(3)]);

        var after = await LoadAsync(db, id);
        after.TimelineEntries.Single().ScreenshotIds.Should().Equal(b, EvidenceNamed(after, "shot-3.png"));
        after.Evidence.Should().HaveCount(3).And.Contain(e => e.Id == a && !e.IsWithdrawn);
        await using (var ctx = db.NewContext())
        {
            var update = await ctx.AuditLog.AsNoTracking()
                .Where(x => x.EntityType == nameof(TimelineEntry) && x.EntityId == stepId.ToString() && x.Action == AuditAction.Update)
                .OrderBy(x => x.Sequence).LastAsync();
            update.BeforeJson.Should().Contain(a.ToString(), "the history keeps what was linked");
            update.Reason.Should().Be("Not this step's");
        }
        await RecordVerifiesAsync(db);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Another_cases_evidence_isnt_linked(string provider)
    {
        var (db, svc, id) = await OpenAsync(provider);
        using var _ = db;
        var other = await NewCaseAsync(svc, "Other");
        await AddAsync(svc, other, [Png(9)]);
        var foreign = (await LoadAsync(db, other)).Evidence.Single().Id;
        var entryId = await AddAsync(svc, id, [Png(1)]);

        var edit = () => svc.EditInvestigationEntryAsync(id, entryId, TimelineEntryType.Analysis, _clock.UtcNow.AddHours(-1),
            "Captured the phishing page", null, keepScreenshots: [foreign]);
        await edit.Should().ThrowAsync<InvalidOperationException>().WithMessage("Only evidence on this case*");
        var add = () => svc.AddTimelineEntryAsync(id, TimelineKind.Investigation, TimelineEntryType.Analysis, _clock.UtcNow,
            "Linked by id", null, evidenceId: foreign);
        await add.Should().ThrowAsync<InvalidOperationException>().WithMessage("Only evidence on this case*");
        (await LoadAsync(db, id)).TimelineEntries.Should().ContainSingle(e => e.IsCurrent && e.MoreEvidenceIds == null);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_screenshot_after_the_first_holds_its_file_on_the_case(string provider)
    {
        var (db, svc, id) = await OpenAsync(provider);
        using var _ = db;
        await AddAsync(svc, id, Pngs(1, 2));
        var second = EvidenceNamed(await LoadAsync(db, id), "shot-2.png");

        var withdraw = () => svc.WithdrawEvidenceAsync(id, second, "Wrong file");
        await withdraw.Should().ThrowAsync<InvalidOperationException>().WithMessage("*screenshot on a timeline entry*");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_entry_with_one_screenshot_is_stored_and_hashed_as_before(string provider)
    {
        var (db, svc, id) = await OpenAsync(provider);
        using var _ = db;
        var entryId = await AddAsync(svc, id, [Png(1)]);
        var entry = (await LoadAsync(db, id)).TimelineEntries.Single(e => e.Id == entryId);
        entry.MoreEvidenceIds.Should().BeNull();
        entry.ScreenshotIds.Should().ContainSingle().Which.Should().Be(entry.EvidenceId!.Value);
        entry.BuildCanonicalContent().Should().EndWith($"|ev|{entry.EvidenceId}").And.NotContain("evs");

        // An edit that leaves it alone carries it to the new version as it was.
        await svc.EditInvestigationEntryAsync(id, entryId, TimelineEntryType.Analysis, _clock.UtcNow.AddHours(-1), "Captured it", null);
        var v2 = (await LoadAsync(db, id)).TimelineEntries.Single(e => e.IsCurrent);
        (v2.EvidenceId, v2.MoreEvidenceIds).Should().Be((entry.EvidenceId, null));
        await RecordVerifiesAsync(db);
    }
}
