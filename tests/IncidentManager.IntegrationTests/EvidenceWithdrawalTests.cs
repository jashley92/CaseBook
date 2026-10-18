using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Evidence;
using IncidentManager.Application.Reporting;
using IncidentManager.Application.Security;
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
/// CAP-21: an evidence file filed on the wrong case is withdrawn with a reason. Nothing is deleted (R3): the bytes, the
/// hash and the custody stay, a "Withdrawn" custody event and an audited update record it, and the row hash covers it
/// (format 5). It leaves the gates' evidence count, the report (its evidence index, its citations, its milestones),
/// citing, a notice's file and an entry's attachment; its milestone says it was withdrawn. It's final; the same file can
/// be uploaded again. Need-to-know holds. On both providers.
/// </summary>
public sealed class EvidenceWithdrawalTests : IDisposable
{
    private readonly HashChainService _hasher = new();
    private static readonly DateTimeOffset Start = new(2026, 10, 18, 9, 0, 0, TimeSpan.Zero);
    private readonly FixedClock _clock = new(Start);
    private readonly TestCurrentUser _user = new() { UserId = "ic1", RoleSet = [AppRole.IncidentCommander] };
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-evidence-withdrawal", Guid.NewGuid().ToString("N"));
    private readonly TestOptionsMonitor<EvidenceStorageOptions> _limits = new(new EvidenceStorageOptions { MinFreeSpaceGB = 0 });
    private readonly CapturingSecurityEventSink _siem = new();

    public static TheoryData<string> Providers => TestDatabase.Providers;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private EvidenceService Evidence(TestDatabase db) =>
        new(db.Factory(), new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Path.Combine(_dir, "store") })),
            _user, _clock, new NoOpAuditWriter(), _limits);

    private CaseService Cases(TestDatabase db, TestCurrentUser? user = null) =>
        new(db.Factory(), user ?? _user, _clock, new CaseNumberGenerator(db.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(), siem: _siem);

    private async Task<(TestDatabase Db, Guid CaseId)> OpenAsync(string provider)
    {
        var db = TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
        var id = (await Cases(db).CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Withdraw", Title = "Mailbox compromise", Classification = Classification.Breach, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, DetectedAtUtc = _clock.UtcNow.AddDays(-2)
        })).Id;
        return (db, id);
    }

    private async Task<Guid> UploadAsync(TestDatabase db, Guid caseId, string name, string content)
    {
        await using var s = new MemoryStream(Encoding.UTF8.GetBytes(content));
        return (await Evidence(db).UploadAsync(caseId, name, "text/plain", s, $"About {name}")).Id;
    }

    private static async Task<Evidence> RowAsync(TestDatabase db, Guid id)
    {
        await using var ctx = db.NewContext();
        return await ctx.Evidence.AsNoTracking().SingleAsync(e => e.Id == id);
    }

    private static async Task<Case> CaseAsync(TestDatabase db, Guid caseId)
    {
        await using var ctx = db.NewContext();
        return await ctx.Cases.AsNoTracking().AsSplitQuery().Include(x => x.Evidence).Include(x => x.TimelineEntries)
            .Include(x => x.Citations).SingleAsync(x => x.Id == caseId);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_file_is_withdrawn_with_a_reason_and_kept_with_its_custody(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var id = await UploadAsync(database, caseId, "wrong-case.csv", "rows");
        var before = await RowAsync(database, id);
        _clock.UtcNow = Start.AddHours(1);
        var cases = Cases(database);

        var blank = () => cases.WithdrawEvidenceAsync(caseId, id, "  ", before.RowHash);
        (await blank.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().Contain("why");
        var stale = () => cases.WithdrawEvidenceAsync(caseId, id, "Wrong case", "v5:not-what-is-there");
        await stale.Should().ThrowAsync<StaleEditException>();

        await cases.WithdrawEvidenceAsync(caseId, id, "  Uploaded to the wrong case; it belongs to 2026-0142 ", before.RowHash);

        var row = await RowAsync(database, id);
        (row.WithdrawnAtUtc, row.WithdrawnBy, row.WithdrawnReason).Should().Be(((DateTimeOffset?)Start.AddHours(1), "ic1",
            "Uploaded to the wrong case; it belongs to 2026-0142"));
        row.IsWithdrawn.Should().BeTrue();
        (row.Sha256, row.SizeBytes, row.StoragePath, row.CreatedAtUtc).Should().Be((before.Sha256, before.SizeBytes, before.StoragePath, before.CreatedAtUtc),
            "the file itself stays (R3)");
        row.RowHash.Should().StartWith(Canonical.V5Prefix);
        _hasher.RowHashMatches(row, row.RowHash!).Should().BeTrue("the row hash covers the withdrawal");
        File.Exists(Path.Combine(_dir, "store", row.StoragePath)).Should().BeTrue("its bytes stay in the store");

        await using (var ctx = database.NewContext())
        {
            var custody = await ctx.CustodyEvents.AsNoTracking().Where(c => c.EvidenceId == id).OrderBy(c => c.AtUtc).ToListAsync();
            custody.Select(c => c.Action).Should().Equal("Uploaded", "Withdrawn");
            custody[1].Details.Should().Be("Uploaded to the wrong case; it belongs to 2026-0142");
            var update = await ctx.AuditLog.AsNoTracking()
                .Where(a => a.EntityType == "Evidence" && a.EntityId == id.ToString() && a.Action == AuditAction.Update).SingleAsync();
            update.Reason.Should().Be("Uploaded to the wrong case; it belongs to 2026-0142");
            update.AfterJson.Should().Contain(nameof(IncidentManager.Domain.Entities.Evidence.WithdrawnReason));
            _hasher.VerifyChain(await ctx.AuditLog.OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
        }
        var sent = _siem.Events.Should().ContainSingle(e => e.EventId == SecurityEventIds.EvidenceWithdrawn).Subject;
        (sent.Severity, sent.TargetType, sent.TargetId, sent.Detail).Should().Be((SecuritySeverity.Warning, "Evidence", id.ToString(), (string?)null),
            "ids only: the reason and the name stay in the audit trail");

        // Final, as a retraction is; the collection can't be changed on it either.
        var again = () => cases.WithdrawEvidenceAsync(caseId, id, "Again");
        (await again.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("already been withdrawn");
        var collect = () => cases.RecordEvidenceCollectionAsync(caseId, id, new EvidenceCollection(null, "WKS-1", null));
        await collect.Should().ThrowAsync<InvalidOperationException>();

        // The same bytes can be uploaded again (a withdrawal by mistake), as a new record with its own custody.
        var again2 = await UploadAsync(database, caseId, "right-case.csv", "rows");
        again2.Should().NotBe(id);
        (await RowAsync(database, again2)).IsWithdrawn.Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_withdrawn_file_leaves_the_gate_count_the_report_and_its_milestone_says_so(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var kept = await UploadAsync(database, caseId, "kept.log", "kept");
        var gone = await UploadAsync(database, caseId, "gone.log", "gone");
        var cases = Cases(database);
        var entry = await cases.AddTimelineEntryAsync(caseId, TimelineKind.Investigation, TimelineEntryType.Analysis, Start.AddMinutes(-30),
            "Reviewed both logs", null);
        await cases.CiteEvidenceAsync(caseId, entry, [kept, gone]);
        var gates = new IncidentManager.Application.StageGates.StageGateEvaluator();
        await using (var ctx = database.NewContext())
            (await gates.BuildFactsAsync(ctx, caseId, default)).EvidenceCount.Should().Be(2);

        await cases.WithdrawEvidenceAsync(caseId, gone, "Belongs to another case");

        await using (var ctx = database.NewContext())
            (await gates.BuildFactsAsync(ctx, caseId, default)).EvidenceCount.Should().Be(1, "AtLeastOneEvidence counts what stands");

        var milestones = CaseMilestones.Project(await CaseAsync(database, caseId), new MilestoneLabels(x => "", s => "", p => "", m => ""));
        var m = milestones.Should().ContainSingle(x => x.Key == $"ev:{gone}").Subject;
        m.Kind.Should().Be(MilestoneKind.EvidenceWithdrawn);
        m.Title.Should().Be("Evidence withdrawn: gone.log (Belongs to another case)");
        m.Actor.Should().Be("ic1");
        milestones.Should().NotContain(x => x.Key == $"ev:{kept}", "a cited file shows on its entry, as before");

        var model = await NewReportService(database).BuildPreviewModelAsync(caseId, null);
        model.Evidence.Select(e => e.FileName).Should().Equal("kept.log");
        model.InvestigationTimeline.Should().Contain(t => t.Description.Contains("Evidence: kept.log.", StringComparison.Ordinal))
            .And.NotContain(t => t.Description.Contains("gone.log", StringComparison.Ordinal), "not in a citation nor a milestone");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_withdrawn_file_can_be_neither_cited_nor_attached_nor_named_as_a_notices_file(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var cited = await UploadAsync(database, caseId, "cited.txt", "cited");
        var other = await UploadAsync(database, caseId, "other.txt", "other");
        var notice = await UploadAsync(database, caseId, "ack.pdf", "ack");
        var cases = Cases(database);
        var entry = await cases.AddTimelineEntryAsync(caseId, TimelineKind.Investigation, TimelineEntryType.Analysis, Start.AddMinutes(-30),
            "Looked at it", null);
        await cases.CiteEvidenceAsync(caseId, entry, [cited]);
        await cases.RecordNoticeAsync(caseId, "NY", Start.AddMinutes(-5), details: new NoticeDetails(NoticeMethod.Portal, "NY-1", null, notice));

        // A notice's file isn't withdrawn while the notice names it.
        var named = () => cases.WithdrawEvidenceAsync(caseId, notice, "Wrong case");
        (await named.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("notice");

        await cases.WithdrawEvidenceAsync(caseId, cited, "Wrong case");
        await cases.WithdrawEvidenceAsync(caseId, other, "Wrong case");

        // Not newly cited; a citation made before stays, and can be taken off.
        var cite = () => cases.CiteEvidenceAsync(caseId, entry, [cited, other]);
        (await cite.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("withdrawn");
        await cases.CiteEvidenceAsync(caseId, entry, [cited]);
        (await CaseAsync(database, caseId)).Citations.Should().ContainSingle(c => c.EvidenceId == cited);
        await cases.CiteEvidenceAsync(caseId, entry, []);
        (await CaseAsync(database, caseId)).Citations.Should().BeEmpty();

        // Not attached to a new entry, nor named as a notice's file (CAP-07).
        var attach = () => cases.AddTimelineEntryAsync(caseId, TimelineKind.Investigation, TimelineEntryType.Analysis, Start.AddMinutes(-20),
            "Screenshot", null, evidenceId: other);
        (await attach.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("withdrawn");
        var asNotice = () => cases.UpdateNoticeDetailsAsync(caseId, "NY", new NoticeDetails(NoticeMethod.Portal, "NY-1", null, other));
        (await asNotice.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("withdrawn");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_restricted_cases_file_cant_be_withdrawn_by_someone_off_it(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var id = await UploadAsync(database, caseId, "hr.msg", "secret");
        await Cases(database).SetRestrictedAsync(caseId, true, "Insider matter");
        var outsider = new TestCurrentUser { UserId = "analyst-unrelated", RoleSet = [AppRole.Analyst] };

        var withdraw = () => Cases(database, outsider).WithdrawEvidenceAsync(caseId, id, "Not mine");
        (await withdraw.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("not found");
        var reader = new TestCurrentUser { UserId = "ic1", RoleSet = [AppRole.IncidentCommander], PermissionSet = [Permission.ViewCases, Permission.ViewRestricted] };
        var noEdit = () => Cases(database, reader).WithdrawEvidenceAsync(caseId, id, "Not allowed");
        await noEdit.Should().ThrowAsync<ForbiddenException>();
        (await RowAsync(database, id)).IsWithdrawn.Should().BeFalse();
    }

    private CaseService Cases(TestDatabase db, IAppDbContextFactory factory) =>
        new(factory, _user, _clock, new CaseNumberGenerator(db.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(), siem: _siem);

    /// <summary>CAP-21 review: what races a withdrawal of the file: a notice naming it, an entry showing it, a second withdrawal.</summary>
    public static TheoryData<string, string, bool> Races
    {
        get
        {
            var rows = new TheoryData<string, string, bool>();
            foreach (var provider in TestDatabase.Providers)
                foreach (var other in new[] { "notice", "entry", "withdraw" })
                    foreach (var withdrawFirst in new[] { true, false })
                        rows.Add(provider, other, withdrawFirst);
            return rows;
        }
    }

    [Theory]
    [MemberData(nameof(Races))]
    public async Task Of_a_withdrawal_and_a_save_naming_the_file_made_from_the_same_reads_exactly_one_lands(string provider, string other,
        bool withdrawFirst)
    {
        // CAP-21 review: the withdrawal read the case untracked, so it took no part in the case's edit version (BUG-113): a
        // notice naming the file saved between its checks and its save (or a second withdrawal) passed as well. Here one
        // writer has made its reads when the other runs whole; the later save must be refused, whichever it is.
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var file = await UploadAsync(database, caseId, "ack.pdf", "ack");
        Func<CaseService, Task> withdraw = s => s.WithdrawEvidenceAsync(caseId, file, "Wrong case");
        Func<CaseService, Task> naming = other switch
        {
            "notice" => s => s.RecordNoticeAsync(caseId, "NY", Start.AddMinutes(-5), details: new NoticeDetails(NoticeMethod.Portal, "NY-1", null, file)),
            "entry" => s => s.AddTimelineEntryAsync(caseId, TimelineKind.Investigation, TimelineEntryType.Analysis, Start.AddMinutes(-20),
                "Screenshot", null, evidenceId: file),
            _ => s => s.WithdrawEvidenceAsync(caseId, file, "Wrong case, said twice"),
        };
        var (outer, inner) = withdrawFirst ? (withdraw, naming) : (naming, withdraw);
        Exception? innerFailed = null;
        var racer = new BeforeFirstSave(async () =>
        {
            try { await inner(Cases(database)); }
            catch (Exception ex) { innerFailed = ex; }
        });
        Exception? outerFailed = null;
        try { await outer(Cases(database, database.FactoryWith(racer))); }
        catch (Exception ex) { outerFailed = ex; }

        new[] { outerFailed, innerFailed }.Count(e => e is null).Should().Be(1, "exactly one of the two lands");
        var refused = (outerFailed ?? innerFailed)!;
        refused.Should().Match<Exception>(e => e is ConcurrentEditException || e is InvalidOperationException,
            "the other is refused in words, never saved alongside");
        await using var ctx = database.NewContext();
        var withdrawn = (await ctx.Evidence.AsNoTracking().SingleAsync(e => e.Id == file)).IsWithdrawn;
        var named = await ctx.JurisdictionNotices.AnyAsync(n => n.EvidenceId == file)
                    || await ctx.TimelineEntries.AnyAsync(t => t.EvidenceId == file && t.IsCurrent);
        (withdrawn && named).Should().BeFalse("nothing on the record points at a withdrawn file");
        (await ctx.CustodyEvents.CountAsync(c => c.EvidenceId == file && c.Action == "Withdrawn")).Should().BeLessThanOrEqualTo(1);
        if (other == "withdraw") withdrawn.Should().BeTrue();
        else (withdrawn || named).Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_withdrawn_copy_isnt_named_as_evidence_elsewhere_and_Find_marks_it(string provider)
    {
        // CAP-21 review: withdrawn from A and uploaded to B, the file on B doesn't say it's "also evidence in" A.
        var (database, a) = await OpenAsync(provider);
        using var _ = database;
        var b = (await Cases(database).CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Right case", Title = "Mailbox compromise", Classification = Classification.Breach, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, DetectedAtUtc = _clock.UtcNow.AddDays(-2)
        })).Id;
        var onA = await UploadAsync(database, a, "quarterly.csv", "rows");
        await Cases(database).WithdrawEvidenceAsync(a, onA, "Belongs to the other case");
        var onB = await UploadAsync(database, b, "quarterly.csv", "rows");
        var evidence = Evidence(database);

        (await evidence.AlsoEvidenceInAsync(onB)).Should().BeEmpty("A's copy is off A's record");
        (await evidence.AlsoEvidenceInAsync(onA)).Should().ContainSingle("the withdrawn copy still says where the file stands");

        var found = (await new IncidentManager.Application.Search.FindService(database.Factory(), _user, new StubUserDirectory())
            .FindAsync("quarterly")).Evidence;
        found.Should().HaveCount(2, "a withdrawn file is still held, so still found");
        found.Single(f => f.Id == onA).IsWithdrawn.Should().BeTrue("but marked");
        found.Single(f => f.Id == onB).IsWithdrawn.Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_withdrawn_file_takes_no_new_task_and_no_recorded_transfer(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var id = await UploadAsync(database, caseId, "wrong.csv", "rows");
        var cases = Cases(database);
        await cases.WithdrawEvidenceAsync(caseId, id, "Wrong case");

        var task = () => cases.AddActionItemAsync(caseId, "Look at it", null, null, about: $"{ActionItem.AboutEvidence}:{id}");
        await task.Should().ThrowAsync<InvalidOperationException>();
        var transfer = () => Evidence(database).RecordTransferAsync(id, "Outside counsel", null, "Litigation");
        (await transfer.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("withdrawn");
        await using var ctx = database.NewContext();
        (await ctx.CustodyEvents.CountAsync(c => c.EvidenceId == id && c.Action == "Transferred")).Should().Be(0);
        (await ctx.ActionItems.CountAsync(t => t.CaseId == caseId && t.AboutRef != null)).Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_withdrawal_reason_of_the_full_length_fits_the_audit_entry(string provider)
    {
        // CAP-21 review: the reason (2,000 characters) is the audit entry's Reason (2,000) and the custody event's Details (2,000).
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var id = await UploadAsync(database, caseId, "long.csv", "rows");
        var reason = new string('r', IncidentManager.Domain.Entities.Evidence.MaxWithdrawnReasonLength);
        await Cases(database).WithdrawEvidenceAsync(caseId, id, reason);
        await using var ctx = database.NewContext();
        (await ctx.AuditLog.AsNoTracking().SingleAsync(a => a.EntityType == "Evidence" && a.EntityId == id.ToString() && a.Action == AuditAction.Update))
            .Reason.Should().Be(reason);
    }

    private ReportService NewReportService(TestDatabase database) =>
        new(database.Factory(), new ReportGenerator(),
            new FileReportStore(Options.Create(new ReportOutputOptions { RootPath = Path.Combine(_dir, "reports") })), _hasher, _user, _clock,
            new IncidentManager.Application.Content.MarkdownService(), new TestOptionsMonitor<ReportingOptions>(new ReportingOptions()),
            new FileReportBrandingStore(Options.Create(new ReportBrandingOptions { RootPath = Path.Combine(_dir, "branding") })),
            new StubUserDirectory(),
            new IncidentManager.Infrastructure.Severities.ConfigurationSeverityLabels(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()));

    private sealed class StubUserDirectory : IUserDirectory
    {
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<UserSummary> All() => [];
        public UserSummary? Resolve(string userId) => null;
        public string DisplayFor(string? userId) => userId ?? "—";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
    }
}
