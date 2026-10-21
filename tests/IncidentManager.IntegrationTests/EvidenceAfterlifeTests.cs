using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Evidence;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using Domain = IncidentManager.Domain;
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
/// A withdrawn file's afterlife: reinstated with a reason within the period an administrator set (and not after, nor once
/// moved or purged); moved to the case it belongs on (copied, checked against its SHA-256, with custody on both sides and
/// withdrawn here); and, once it can't be reinstated, purged by an administrator: its bytes deleted, its record, hash and
/// custody kept, and no longer read by downloads or the re-check. Never under a legal hold. On both providers.
/// </summary>
public sealed class EvidenceAfterlifeTests : IDisposable
{
    private readonly HashChainService _hasher = new();
    private static readonly DateTimeOffset Start = new(2026, 10, 18, 9, 0, 0, TimeSpan.Zero);
    private readonly FixedClock _clock = new(Start);
    private readonly TestCurrentUser _user = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin, AppRole.IncidentCommander, AppRole.LegalPrivacy] };
    private readonly TestCurrentUser _analyst = new() { UserId = "analyst1", RoleSet = [AppRole.Analyst] };
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-evidence-afterlife", Guid.NewGuid().ToString("N"));
    private readonly TestOptionsMonitor<EvidenceStorageOptions> _limits = new(new EvidenceStorageOptions { MinFreeSpaceGB = 0, ReinstateWithinDays = 30 });
    private readonly CapturingSecurityEventSink _siem = new();

    public static TheoryData<string> Providers => TestDatabase.Providers;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private FileEvidenceStore Store() => new(Options.Create(new EvidenceStoreOptions { RootPath = Path.Combine(_dir, "store") }));

    private EvidenceService Evidence(TestDatabase db, TestCurrentUser? user = null) =>
        new(db.Factory(), Store(), user ?? _user, _clock, new NoOpAuditWriter(), _limits);

    private CaseService Cases(TestDatabase db, TestCurrentUser? user = null) =>
        new(db.Factory(), user ?? _user, _clock, new CaseNumberGenerator(db.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
            evidenceStore: Store(), evidenceLimits: _limits, siem: _siem);

    private async Task<Guid> OpenCaseAsync(TestDatabase db, string name) =>
        (await Cases(db).CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = name, Title = name, Classification = Classification.Incident, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, DetectedAtUtc = _clock.UtcNow.AddDays(-2)
        })).Id;

    private async Task<Guid> UploadAsync(TestDatabase db, Guid caseId, string name, string content)
    {
        await using var s = new MemoryStream(Encoding.UTF8.GetBytes(content));
        return (await Evidence(db).UploadAsync(caseId, name, "text/plain", s, $"About {name}")).Id;
    }

    private static async Task<Evidence> RowAsync(TestDatabase db, Guid id)
    {
        await using var ctx = db.NewContext();
        return await ctx.Evidence.AsNoTracking().Include(e => e.CustodyEvents).SingleAsync(e => e.Id == id);
    }

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));

    private async Task ChainIsValidAsync(TestDatabase db)
    {
        await using var ctx = db.NewContext();
        _hasher.VerifyChain(await ctx.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_withdrawn_file_is_reinstated_with_a_reason_within_the_period_and_not_after(string provider)
    {
        using var db = Open(provider);
        var caseId = await OpenCaseAsync(db, "Reinstate");
        var a = await UploadAsync(db, caseId, "a.txt", "first");
        var b = await UploadAsync(db, caseId, "b.txt", "second");
        await Cases(db).WithdrawEvidenceAsync(caseId, a, "Wrong case, I thought");
        await Cases(db).WithdrawEvidenceAsync(caseId, b, "Wrong case");

        var noReason = () => Cases(db).ReinstateEvidenceAsync(caseId, a, " ");
        await noReason.Should().ThrowAsync<ArgumentException>();
        _clock.UtcNow = _clock.UtcNow.AddMinutes(5);   // a later moment, so the custody log orders them by time
        await Cases(db).ReinstateEvidenceAsync(caseId, a, "It was this case's after all");
        var back = await RowAsync(db, a);
        back.IsWithdrawn.Should().BeFalse();
        // In time order: SQL Server returns the rows in no particular order.
        back.CustodyEvents.OrderBy(c => c.AtUtc).Select(c => c.Action).Should().ContainInOrder("Withdrawn", "Reinstated");
        _siem.Events.Should().Contain(e => e.EventId == SecurityEventIds.EvidenceReinstated);

        _clock.UtcNow = Start.AddDays(31);
        var late = () => Cases(db).ReinstateEvidenceAsync(caseId, b, "Too late");
        (await late.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("final");
        (await RowAsync(db, b)).IsWithdrawn.Should().BeTrue();
        await ChainIsValidAsync(db);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_file_on_the_wrong_case_is_moved_with_its_bytes_checked_and_custody_on_both_sides(string provider)
    {
        using var db = Open(provider);
        var wrong = await OpenCaseAsync(db, "Wrong");
        var right = await OpenCaseAsync(db, "Right");
        string rightNumber;
        await using (var ctx = db.NewContext()) rightNumber = (await ctx.Cases.SingleAsync(c => c.Id == right)).CaseNumber;
        var ev = await UploadAsync(db, wrong, "phish.eml", "Subject: invoice");

        var wrongNumber = await RowCaseNumberAsync(db, wrong);
        var self = () => Cases(db).MoveEvidenceAsync(wrong, ev, wrongNumber, "Same");
        await self.Should().ThrowAsync<ArgumentException>();
        var moved = await Cases(db).MoveEvidenceAsync(wrong, ev, rightNumber, "Filed on the wrong case");

        var left = await RowAsync(db, ev);
        left.IsWithdrawn.Should().BeTrue();
        left.WithdrawnReason.Should().Contain(rightNumber);
        left.CustodyEvents.Should().Contain(c => c.Action == Domain.Entities.Evidence.MovedOutAction);
        var copy = await RowAsync(db, moved);
        copy.CaseId.Should().Be(right);
        copy.Sha256.Should().Be(left.Sha256);
        copy.StoragePath.Should().NotBe(left.StoragePath, "the copy has its own file in the right case's folder");
        copy.Description.Should().Be(left.Description);
        copy.CustodyEvents.Should().ContainSingle(c => c.Action == Domain.Entities.Evidence.MovedInAction).Which.Details.Should().Contain("Filed on the wrong case");
        await using (var read = (await Evidence(db).OpenAsync(moved, recordDownload: false)).Content)
            new StreamReader(read).ReadToEnd().Should().Be("Subject: invoice");

        var reinstate = () => Cases(db).ReinstateEvidenceAsync(wrong, ev, "Back");
        await reinstate.Should().ThrowAsync<InvalidOperationException>().WithMessage("*moved*");
        _siem.Events.Should().Contain(e => e.EventId == SecurityEventIds.EvidenceMoved);
        await ChainIsValidAsync(db);
    }

    private static async Task<string> RowCaseNumberAsync(TestDatabase db, Guid caseId)
    {
        await using var ctx = db.NewContext();
        return (await ctx.Cases.SingleAsync(c => c.Id == caseId)).CaseNumber;
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_administrator_purges_a_withdrawn_file_once_it_cant_be_reinstated_and_its_record_stays(string provider)
    {
        using var db = Open(provider);
        var caseId = await OpenCaseAsync(db, "Purge");
        var ev = await UploadAsync(db, caseId, "personal.csv", "name,ssn");
        var path = Path.Combine(_dir, "store", (await RowAsync(db, ev)).StoragePath);
        File.Exists(path).Should().BeTrue();

        var standing = () => Cases(db).PurgeEvidenceAsync(caseId, ev, "PII");
        await standing.Should().ThrowAsync<InvalidOperationException>().WithMessage("Withdraw the file first*");
        await Cases(db).WithdrawEvidenceAsync(caseId, ev, "Personal data uploaded by mistake");
        var early = () => Cases(db).PurgeEvidenceAsync(caseId, ev, "PII");
        await early.Should().ThrowAsync<InvalidOperationException>().WithMessage("*can still be reinstated*");
        var analyst = () => Cases(db, _analyst).PurgeEvidenceAsync(caseId, ev, "PII");
        await analyst.Should().ThrowAsync<ForbiddenException>();

        _clock.UtcNow = Start.AddDays(31);
        var listed = await Cases(db).ListWithdrawnEvidenceAsync();
        listed.Should().ContainSingle(r => r.EvidenceId == ev).Which.Purgeable.Should().BeTrue();

        await Cases(db).PurgeEvidenceAsync(caseId, ev, "Personal data; Legal asked for it to be deleted");
        File.Exists(path).Should().BeFalse("its bytes are deleted");
        var row = await RowAsync(db, ev);
        row.IsPurged.Should().BeTrue();
        row.Sha256.Should().NotBeEmpty("the record and hash stay");
        row.CustodyEvents.Select(c => c.Action).Should().Contain("Purged");
        var download = () => Evidence(db).OpenAsync(ev);
        (await download.Should().ThrowAsync<IncidentManager.Application.Common.NotFoundException>()).Which.Message.Should().Contain("purged");
        (await Cases(db).ListWithdrawnEvidenceAsync()).Should().NotContain(r => r.EvidenceId == ev);
        (await Evidence(db).StorageUseAsync()).UsedBytes.Should().Be(0, "a purged file takes no space");
        var reinstate = () => Cases(db).ReinstateEvidenceAsync(caseId, ev, "Back");
        await reinstate.Should().ThrowAsync<InvalidOperationException>().WithMessage("*purged*");
        _siem.Events.Should().Contain(e => e.EventId == SecurityEventIds.EvidencePurged);
        await ChainIsValidAsync(db);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Nothing_is_purged_from_a_case_under_a_legal_hold(string provider)
    {
        using var db = Open(provider);
        var caseId = await OpenCaseAsync(db, "Hold");
        var ev = await UploadAsync(db, caseId, "kept.txt", "keep me");
        await Cases(db).WithdrawEvidenceAsync(caseId, ev, "Wrong case");
        await Cases(db).SetLegalHoldAsync(caseId, true, "Litigation");
        _clock.UtcNow = Start.AddDays(31);

        (await Cases(db).ListWithdrawnEvidenceAsync()).Single(r => r.EvidenceId == ev).Purgeable.Should().BeFalse();
        var purge = () => Cases(db).PurgeEvidenceAsync(caseId, ev, "Please");
        await purge.Should().ThrowAsync<InvalidOperationException>().WithMessage("*legal hold*");
        File.Exists(Path.Combine(_dir, "store", (await RowAsync(db, ev)).StoragePath)).Should().BeTrue();
    }
}
