using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Evidence;
using IncidentManager.Domain.Common;
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
/// CAP-08: an evidence file records when, where from and by whom it was collected: on every upload path (in the page,
/// a pasted screenshot, a drop, in parts), through a cut-off and a restart of a large upload, and later in the evidence
/// panel as an audited change. The time is held to the case's own times; a file without a collection hashes exactly as
/// before; the "Evidence added" milestone is dated at collection and says it was recorded later; need-to-know holds.
/// On both providers.
/// </summary>
public sealed class EvidenceCollectionTests : IDisposable
{
    private readonly HashChainService _hasher = new();
    private static readonly DateTimeOffset Start = new(2026, 10, 17, 9, 0, 0, TimeSpan.Zero);
    private readonly FixedClock _clock = new(Start);
    private readonly TestCurrentUser _user = new() { UserId = "ic1", RoleSet = [AppRole.IncidentCommander] };
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-evidence-collection", Guid.NewGuid().ToString("N"));
    private readonly TestOptionsMonitor<EvidenceStorageOptions> _limits = new(new EvidenceStorageOptions { MinFreeSpaceGB = 0 });
    private readonly EvidenceUploadSessions _uploads = new();

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private const int Part = EvidenceUploadSessions.PartBytes;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private FileEvidenceStore Files() => new(Options.Create(new EvidenceStoreOptions { RootPath = Path.Combine(_dir, "store") }));

    private EvidenceService Evidence(TestDatabase db, TestCurrentUser? user = null, EvidenceUploadSessions? uploads = null) =>
        new(db.Factory(), Files(), user ?? _user, _clock, new NoOpAuditWriter(), _limits, uploads ?? _uploads);

    private CaseService Cases(TestDatabase db, TestCurrentUser? user = null) =>
        new(db.Factory(), user ?? _user, _clock, new CaseNumberGenerator(db.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private static DateTimeOffset Began => Start.AddDays(-5);

    // A case whose activity began five days ago and was detected two days ago (or with no activity time recorded).
    private async Task<(TestDatabase Db, Guid CaseId)> OpenAsync(string provider, bool activityKnown = true)
    {
        var db = TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
        var id = (await Cases(db).CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Collect", Title = "Mailbox compromise", Classification = Classification.Incident, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, DetectedAtUtc = _clock.UtcNow.AddDays(-2), OccurredAtUtc = activityKnown ? Began : null
        })).Id;
        return (db, id);
    }

    private static MemoryStream Bytes(string s) => new(Encoding.UTF8.GetBytes(s));

    private string[] StoredFiles() =>
        Directory.Exists(Path.Combine(_dir, "store"))
            ? Directory.GetFiles(Path.Combine(_dir, "store"), "*", SearchOption.AllDirectories)
                .Where(f => !Path.GetFileName(f).StartsWith(".probe-", StringComparison.Ordinal)).ToArray()
            : [];

    private static async Task<Evidence> RowAsync(TestDatabase db, Guid id)
    {
        await using var ctx = db.NewContext();
        return await ctx.Evidence.AsNoTracking().SingleAsync(e => e.Id == id);
    }

    private static async Task SendAllAsync(EvidenceService svc, EvidenceService.UploadStarted started, byte[] bytes)
    {
        for (var i = 0; i < started.Parts; i++)
            await svc.AppendPartAsync(started.Id, i, bytes.AsMemory(i * Part, Math.Min(Part, bytes.Length - i * Part)));
    }

    private static string SampleOf(byte[] b) =>
        Convert.ToHexString(SHA256.HashData(b.AsSpan(0, Math.Min(b.Length, 1024 * 1024)))).ToLowerInvariant();

    private void ShouldHold(Evidence row, DateTimeOffset at, string from, string by)
    {
        row.CollectedAtUtc.Should().Be(at);
        row.CollectedFrom.Should().Be(from);
        row.CollectedBy.Should().Be(by);
        _hasher.RowHashMatches(row, row.RowHash!).Should().BeTrue("the row hash covers the collection it was saved with");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Each_upload_path_records_when_where_from_and_by_whom_it_was_collected(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var svc = Evidence(database);
        var at = _clock.UtcNow.AddHours(-6);
        var collected = new EvidenceCollection(at, "  WKS-0142 ", " J. Rivera (EDR live response) ");

        // In the page (a picked file).
        await using (var s = Bytes("picked"))
            ShouldHold(await RowAsync(database, (await svc.UploadAsync(caseId, "triage.zip", "application/zip", s, "KAPE triage", 6, collected)).Id),
                at, "WKS-0142", "J. Rivera (EDR live response)");

        // A pasted screenshot is staged in the picker, so it goes the same way.
        await using (var s = Bytes("png-bytes"))
            ShouldHold(await RowAsync(database, (await svc.UploadAsync(caseId, "screenshot.png", "image/png", s, null, null, collected)).Id),
                at, "WKS-0142", "J. Rivera (EDR live response)");

        // A drop: one in-page upload per file, each with the form's collection.
        foreach (var name in new[] { "Security.evtx", "System.evtx" })
            await using (var s = Bytes(name))
                ShouldHold(await RowAsync(database, (await svc.UploadAsync(caseId, name, "", s, null, null, collected)).Id),
                    at, "WKS-0142", "J. Rivera (EDR live response)");

        // In parts (over 100 MB in the page): the begin request carries it.
        var bytes = RandomNumberGenerator.GetBytes(Part + 321);
        var started = await svc.BeginUploadAsync(caseId, "memory.dmp", "", bytes.Length, null, null, collected);
        await SendAllAsync(svc, started, bytes);
        ShouldHold(await RowAsync(database, (await svc.CompleteUploadAsync(started.Id)).Id), at, "WKS-0142", "J. Rivera (EDR live response)");

        // Without one, nothing is recorded, as before.
        await using (var s = Bytes("plain"))
        {
            var plain = await RowAsync(database, (await svc.UploadAsync(caseId, "plain.txt", "text/plain", s, null)).Id);
            plain.HasCollection.Should().BeFalse();
            plain.CollectedOrUploadedAtUtc.Should().Be(plain.CreatedAtUtc);
        }
        await using var ctx = database.NewContext();
        _hasher.VerifyChain(await ctx.AuditLog.OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_large_upload_keeps_its_collection_when_cut_off_and_through_a_restart(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var at = _clock.UtcNow.AddDays(-1);
        var collected = new EvidenceCollection(at, "mx01.contoso.example", "Messaging team");
        var bytes = RandomNumberGenerator.GetBytes(2 * Part + 99);
        var before = Evidence(database);
        var started = await before.BeginUploadAsync(caseId, "journal.pst", "", bytes.Length, null, SampleOf(bytes), collected);
        await before.AppendPartAsync(started.Id, 0, bytes.AsMemory(0, Part));

        // The app restarts: the saved state is read back into new session memory.
        var afterUploads = new EvidenceUploadSessions();
        (await EvidenceService.RestoreUploadsAsync(afterUploads, Files())).Should().Be(1);
        var after = Evidence(database, uploads: afterUploads);
        (await after.ResumeUploadAsync(started.Id, "journal.pst", bytes.Length, SampleOf(bytes))).NextPart.Should().Be(1);
        await after.AppendPartAsync(started.Id, 1, bytes.AsMemory(Part, Part));
        await after.AppendPartAsync(started.Id, 2, bytes.AsMemory(2 * Part, 99));

        ShouldHold(await RowAsync(database, (await after.CompleteUploadAsync(started.Id)).Id), at, "mx01.contoso.example", "Messaging team");
    }

    [Fact]
    public void An_upload_state_saved_before_collections_were_kept_still_restores()
    {
        // As v1.9.0 wrote it: no collection fields.
        var id = new string('a', 32);
        var json = System.Text.Json.JsonSerializer.Serialize(new
        {
            id, userId = "ic1", caseId = Guid.NewGuid(), fileName = "disk.img", contentType = "", description = (string?)null,
            size = 10L, incoming = "inc-1", nextPart = 0, committed = 0L, partHashes = Array.Empty<string>(), sample = (string?)null,
            pendingPart = -1, pendingHash = (string?)null, lastActivity = _clock.UtcNow
        });
        var uploads = new EvidenceUploadSessions();
        uploads.Restore("inc-1", json).Should().BeTrue();
        uploads.Find(id, "ic1")!.Collected.Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_collection_time_the_case_rules_out_is_refused_before_a_byte_is_stored(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var svc = Evidence(database);

        async Task Refused(EvidenceCollection collected, string why)
        {
            await using (var s = Bytes("x"))
            {
                var inPage = () => svc.UploadAsync(caseId, "a.txt", "text/plain", s, null, 1, collected);
                (await inPage.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().Contain(why);
            }
            var inParts = () => svc.BeginUploadAsync(caseId, "b.bin", "", 2L * Part, null, null, collected);
            (await inParts.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().Contain(why);
        }

        await Refused(new(_clock.UtcNow.AddMinutes(5), null, null), "in the future");
        await Refused(new(Began.AddMinutes(-1), null, null), "before the case's activity began");
        await Refused(new(null, new string('h', Domain.Entities.Evidence.MaxCollectedFromLength + 1), null), "collected from");
        await Refused(new(null, null, new string('p', Domain.Entities.Evidence.MaxCollectedByLength + 1)), "who collected it");
        StoredFiles().Should().BeEmpty("each was refused before its bytes were stored");
        await using (var ctx = database.NewContext()) (await ctx.Evidence.CountAsync()).Should().Be(0);

        // The edges pass: when the activity began, and now (to the minute).
        await using (var s = Bytes("first"))
            (await svc.UploadAsync(caseId, "first.txt", "text/plain", s, null, null, new(Began, null, null))).CollectedAtUtc.Should().Be(Began);
        await using (var s = Bytes("now"))
            (await svc.UploadAsync(caseId, "now.txt", "text/plain", s, null, null, new(_clock.UtcNow.AddSeconds(30), null, null)))
                .CollectedAtUtc.Should().NotBeNull();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Without_an_activity_time_the_collection_cant_be_before_detection(string provider)
    {
        var (database, caseId) = await OpenAsync(provider, activityKnown: false);
        using var _ = database;
        await using var s = Bytes("x");
        var early = () => Evidence(database).UploadAsync(caseId, "a.txt", "text/plain", s, null, 1,
            new EvidenceCollection(_clock.UtcNow.AddDays(-3), null, null));
        (await early.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().Contain("before the case's activity began");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_file_without_a_collection_hashes_exactly_as_it_did_before(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        Guid id;
        await using (var s = Bytes("export"))
            id = (await Evidence(database).UploadAsync(caseId, "a|b.csv", "text/csv", s, "export")).Id;
        var row = await RowAsync(database, id);

        Canonical.InFormat(5, row.BuildCanonicalContent).Should().Be(Canonical.InFormat(4, row.BuildCanonicalContent),
            "format 5 adds nothing for a file without a collection (R7), so its hash is the one it always had");
        Canonical.Covers(4, row.BuildCanonicalContent).Should().BeTrue();
        _hasher.RowHashMatches(row, row.RowHash!).Should().BeTrue();

        row.CollectedFrom = "WKS-0142";
        Canonical.Covers(4, row.BuildCanonicalContent).Should().BeFalse("a format-4 hash can't show a collection");
        _hasher.RowHashMatches(row, row.RowHash!).Should().BeFalse("set outside CaseBook, it no longer matches");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_evidence_added_milestone_is_dated_at_collection_and_says_it_was_recorded_later(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var svc = Evidence(database);
        var earlier = _clock.UtcNow.AddHours(-3);
        Guid late, plain, sameMinute;
        await using (var s = Bytes("late"))
            late = (await svc.UploadAsync(caseId, "late.eml", "message/rfc822", s, "Phish sample", null,
                new EvidenceCollection(earlier, "j.doe mailbox", "Messaging team"))).Id;
        await using (var s = Bytes("plain"))
            plain = (await svc.UploadAsync(caseId, "plain.txt", "text/plain", s, null)).Id;
        _clock.UtcNow = Start.AddSeconds(40);
        await using (var s = Bytes("same"))
            sameMinute = (await svc.UploadAsync(caseId, "same.txt", "text/plain", s, null, null,
                new EvidenceCollection(Start.AddSeconds(10), null, null))).Id;

        await using var ctx = database.NewContext();
        var c = await ctx.Cases.AsNoTracking().AsSplitQuery().Include(x => x.Evidence).Include(x => x.TimelineEntries)
            .Include(x => x.Citations).SingleAsync(x => x.Id == caseId);
        var milestones = CaseMilestones.Project(c, new MilestoneLabels(x => "", s => "", p => "", m => ""))
            .Where(m => m.Kind == MilestoneKind.EvidenceAdded).ToDictionary(m => m.Key);

        var m1 = milestones[$"ev:{late}"];
        m1.AtUtc.Should().Be(earlier, "dated when it was collected");
        m1.RecordedAtUtc.Should().Be(Start, "and recorded later, when it was uploaded");
        m1.Detail.Should().Be("Phish sample. Collected from j.doe mailbox by Messaging team.");
        var m2 = milestones[$"ev:{plain}"];
        (m2.AtUtc, m2.RecordedAtUtc, m2.Detail).Should().Be((Start, (DateTimeOffset?)null, (string?)null), "as before");
        milestones[$"ev:{sameMinute}"].RecordedAtUtc.Should().BeNull("collected in the minute it was uploaded isn't late");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_collection_recorded_later_is_an_audited_change_and_a_stale_one_is_refused(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        Guid id;
        await using (var s = Bytes("disk"))
            id = (await Evidence(database).UploadAsync(caseId, "disk.e01", "", s, "Image")).Id;
        var uploaded = await RowAsync(database, id);
        _clock.UtcNow = _clock.UtcNow.AddHours(2);
        var cases = Cases(database);
        var at = uploaded.CreatedAtUtc.AddHours(-20);

        (await cases.RecordEvidenceCollectionAsync(caseId, id, new EvidenceCollection(at, "WKS-0142", "DFIR vendor"),
            EvidenceCollection.None)).Should().BeTrue();

        var row = await RowAsync(database, id);
        ShouldHold(row, at, "WKS-0142", "DFIR vendor");
        (row.Sha256, row.SizeBytes, row.StoragePath, row.CreatedAtUtc).Should().Be((uploaded.Sha256, uploaded.SizeBytes, uploaded.StoragePath, uploaded.CreatedAtUtc),
            "the file itself never changes (R3)");
        row.ModifiedBy.Should().Be("ic1");
        await using (var ctx = database.NewContext())
        {
            var update = await ctx.AuditLog.AsNoTracking()
                .Where(a => a.EntityType == "Evidence" && a.EntityId == id.ToString() && a.Action == AuditAction.Update).SingleAsync();
            update.Actor.Should().Be("ic1");
            update.AfterJson.Should().Contain("CollectedFrom").And.Contain("WKS-0142").And.Contain("DFIR vendor");
            update.CaseNumber.Should().NotBeNullOrEmpty();
            _hasher.VerifyChain(await ctx.AuditLog.OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
        }

        // The same again changes nothing and records nothing.
        var current = EvidenceCollection.Of(row);
        (await cases.RecordEvidenceCollectionAsync(caseId, id, current, current)).Should().BeFalse();
        // A panel opened before that change is refused, not saved over it.
        var stale = () => cases.RecordEvidenceCollectionAsync(caseId, id, new EvidenceCollection(null, "WKS-9999", null), EvidenceCollection.None);
        await stale.Should().ThrowAsync<StaleEditException>();
        // The time can't be after the upload, or before the activity began.
        var afterUpload = () => cases.RecordEvidenceCollectionAsync(caseId, id, new EvidenceCollection(uploaded.CreatedAtUtc.AddMinutes(30), null, null));
        (await afterUpload.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().Contain("after it was uploaded");
        var tooEarly = () => cases.RecordEvidenceCollectionAsync(caseId, id, new EvidenceCollection(Began.AddHours(-1), null, null));
        (await tooEarly.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().Contain("activity began");

        // Cleared, it's taken to be the upload again; the trail keeps what it was.
        (await cases.RecordEvidenceCollectionAsync(caseId, id, EvidenceCollection.None, current)).Should().BeTrue();
        var cleared = await RowAsync(database, id);
        cleared.HasCollection.Should().BeFalse();
        _hasher.RowHashMatches(cleared, cleared.RowHash!).Should().BeTrue();
        await using (var ctx = database.NewContext())
            (await ctx.AuditLog.CountAsync(a => a.EntityType == "Evidence" && a.EntityId == id.ToString() && a.Action == AuditAction.Update))
                .Should().Be(2);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_restricted_cases_evidence_can_be_neither_uploaded_to_nor_edited_by_someone_off_it(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        Guid id;
        await using (var s = Bytes("secret"))
            id = (await Evidence(database).UploadAsync(caseId, "hr.msg", "", s, null)).Id;
        await Cases(database).SetRestrictedAsync(caseId, true, "Insider matter");
        var outsider = new TestCurrentUser { UserId = "analyst-unrelated", RoleSet = [AppRole.Analyst] };

        var edit = () => Cases(database, outsider).RecordEvidenceCollectionAsync(caseId, id, new EvidenceCollection(null, "WKS-1", null));
        (await edit.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("not found");
        await using (var s = Bytes("more"))
        {
            var upload = () => Evidence(database, outsider).UploadAsync(caseId, "x.txt", "", s, null, 4, new EvidenceCollection(null, "WKS-1", null));
            (await upload.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("not found");
        }
        var inParts = () => Evidence(database, outsider).BeginUploadAsync(caseId, "y.bin", "", 2L * Part, null, null, new EvidenceCollection(null, "WKS-1", null));
        await inParts.Should().ThrowAsync<InvalidOperationException>();
        (await RowAsync(database, id)).HasCollection.Should().BeFalse();

        // Nor through another case it can see: the file must be on the case named.
        var other = (await Cases(database).CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Other", Title = "Other", Classification = Classification.Incident, Severity = Severity.Low,
            Origin = CaseOrigin.InternalDetection, DetectedAtUtc = _clock.UtcNow.AddDays(-1)
        })).Id;
        var elsewhere = () => Cases(database).RecordEvidenceCollectionAsync(other, id, new EvidenceCollection(null, "WKS-1", null));
        (await elsewhere.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("isn't on this case");
    }
}
