using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using ICSharpCode.SharpZipLib.Zip;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Common;
using IncidentManager.Application.Evidence;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using IncidentManager.Web.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-12: a case's evidence packaged for hand-over: one zip with the password "infected" holding the files picked (every
/// file that stands by default; never a withdrawn one, CAP-21) under their base names, never colliding, and a MANIFEST.txt.
/// Each file's bytes match its recorded SHA-256, checked before any of it is sent. CAP-12 review: before the first byte,
/// each file gets a "Transfer begun" custody event and the audit trail an entry naming the package; sent in full, each
/// gets "Transferred" and the trail an entry with the package's SHA-256; stopped part-way (cut off, a store or key outage,
/// a file that no longer matches), the record says how far each file got, since what went out can be read from the zip
/// without its directory. Custody and its audit entry are written together. The size cap, the single-use ticket and
/// need-to-know hold. On both providers.
/// </summary>
public sealed class EvidencePackageTests : IDisposable
{
    private readonly HashChainService _hasher = new();
    private static readonly DateTimeOffset Start = new(2026, 10, 18, 9, 0, 0, TimeSpan.Zero);
    private readonly FixedClock _clock = new(Start);
    private readonly TestCurrentUser _user = new() { UserId = "ic1", RoleSet = [AppRole.IncidentCommander] };
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-evidence-package", Guid.NewGuid().ToString("N"));
    private readonly TestOptionsMonitor<EvidenceStorageOptions> _limits = new(new EvidenceStorageOptions { MinFreeSpaceGB = 0 });
    private readonly EvidencePackageTickets _tickets = new();
    private readonly CapturingAudit _audit = new();
    private readonly FailingSaves _failing = new();

    public static TheoryData<string> Providers => TestDatabase.Providers;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private FileEvidenceStore Files() => new(Options.Create(new EvidenceStoreOptions { RootPath = Path.Combine(_dir, "store") }));

    private EvidenceService Evidence(TestDatabase db, TestCurrentUser? user = null, IEvidenceStore? store = null, IAuditWriter? audit = null) =>
        new(db.Factory(), store ?? Files(), user ?? _user, _clock, audit ?? _audit, _limits, packages: _tickets);

    private CaseService Cases(TestDatabase db, TestCurrentUser? user = null) =>
        new(db.Factory(), user ?? _user, _clock, new CaseNumberGenerator(db.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
            evidenceLimits: _limits, evidencePackages: _tickets);

    private async Task<(TestDatabase Db, Guid CaseId)> OpenAsync(string provider)
    {
        // Ahead of the chain, so a failed save never holds its gate.
        var db = TestDatabase.Open(provider, _failing, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
        var id = (await Cases(db).CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Hand-over", Title = "Ransomware", Classification = Classification.Breach, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, DetectedAtUtc = _clock.UtcNow.AddDays(-2)
        })).Id;
        return (db, id);
    }

    private async Task<Guid> UploadAsync(TestDatabase db, Guid caseId, string name, byte[] content, EvidenceCollection? collected = null)
    {
        await using var s = new MemoryStream(content);
        return (await Evidence(db).UploadAsync(caseId, name, "application/octet-stream", s, null, content.Length, collected)).Id;
    }

    private static byte[] Text(string s) => Encoding.UTF8.GetBytes(s);
    private static string Sha(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();

    // What the endpoint does once the ticket is taken: record the start, then send the zip and record how it ended.
    private static async Task<(byte[] Zip, EvidencePackage Package)> DownloadAsync(EvidenceService svc, string ticket)
    {
        var package = await svc.OpenPackageAsync(ticket);
        await svc.RecordPackageBegunAsync(package);
        using var output = new MemoryStream();
        (await EvidencePackageEndpoints.SendAsync(package, svc.ManifestOf(package), svc, NullLogger.Instance, output, default))
            .Should().BeTrue();
        return (output.ToArray(), package);
    }

    // A package begun and sent as far as it goes, with what the log said.
    private static async Task<(bool Whole, byte[] Sent, EvidencePackage Package, ListLogger Log)> SendAsync(EvidenceService svc, string ticket,
        CancellationToken ct = default)
    {
        var package = await svc.OpenPackageAsync(ticket, CancellationToken.None);
        await svc.RecordPackageBegunAsync(package, CancellationToken.None);
        var log = new ListLogger();
        using var output = new MemoryStream();
        var whole = await EvidencePackageEndpoints.SendAsync(package, svc.ManifestOf(package), svc, log, output, ct);
        return (whole, output.ToArray(), package, log);
    }

    // What a recipient can read from a zip without its directory (from its local headers, as ZipInputStream and 7-Zip
    // do): each entry's name and the bytes that could be read, and whether it was whole.
    private static List<(string Name, byte[] Bytes, bool Whole)> Recover(byte[] sent)
    {
        var found = new List<(string, byte[], bool)>();
        using var zip = new ZipInputStream(new MemoryStream(sent)) { Password = EvidenceRisk.ZipPassword };
        while (true)
        {
            ZipEntry? e;
            try { e = zip.GetNextEntry(); }
            catch (Exception ex) when (ex is ZipException or EndOfStreamException or IOException) { break; }
            if (e is null) break;
            using var m = new MemoryStream();
            var buffer = new byte[4096];
            var whole = true;
            try
            {
                int n;
                while ((n = zip.Read(buffer, 0, buffer.Length)) > 0) m.Write(buffer, 0, n);
            }
            catch (Exception ex) when (ex is ZipException or EndOfStreamException or IOException or ICSharpCode.SharpZipLib.SharpZipBaseException) { whole = false; }
            found.Add((e.Name, m.ToArray(), whole));
            if (!whole) break;
        }
        return found;
    }

    private static async Task<List<ChainOfCustodyEvent>> CustodyAsync(TestDatabase db, Guid packageId)
    {
        await using var ctx = db.NewContext();
        var id = packageId.ToString();
        return (await ctx.CustodyEvents.AsNoTracking().ToListAsync()).Where(c => c.Details?.Contains(id, StringComparison.Ordinal) == true)
            .OrderBy(c => c.AtUtc).ToList();
    }

    private static async Task<List<string>> PackageAuditAsync(TestDatabase db, Guid packageId)
    {
        await using var ctx = db.NewContext();
        var id = packageId.ToString();
        return await ctx.AuditLog.AsNoTracking().Where(a => a.EntityType == "EvidencePackage" && a.EntityId == id)
            .OrderBy(a => a.Sequence).Select(a => a.Summary ?? "").ToListAsync();
    }

    private static Dictionary<string, byte[]> Unzip(byte[] zip)
    {
        using var file = new ZipFile(new MemoryStream(zip)) { Password = EvidenceRisk.ZipPassword };
        var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (ZipEntry e in file)
        {
            e.IsCrypted.Should().BeTrue("every entry is behind the password, the manifest too");
            e.CompressionMethod.Should().Be(CompressionMethod.Deflated);
            using var s = file.GetInputStream(e);
            using var m = new MemoryStream();
            s.CopyTo(m);
            entries[e.Name] = m.ToArray();
        }
        return entries;
    }

    private static async Task<List<ChainOfCustodyEvent>> TransfersAsync(TestDatabase db)
    {
        await using var ctx = db.NewContext();
        return await ctx.CustodyEvents.AsNoTracking().Where(c => c.Action == "Transferred").ToListAsync();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_package_opens_with_infected_and_holds_each_file_and_a_manifest_that_match_their_SHA_256s(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var (a, b, c, d) = (Text("first notes"), Text("second notes"), Text("not the manifest"), RandomNumberGenerator.GetBytes(300_000));
        var ida = await UploadAsync(database, caseId, "notes.txt", a, new EvidenceCollection(Start.AddHours(-5), "WKS-0142", "J. Rivera"));
        _clock.UtcNow = Start.AddMinutes(1);
        var idb = await UploadAsync(database, caseId, "NOTES.txt", b);
        _clock.UtcNow = Start.AddMinutes(2);
        var idc = await UploadAsync(database, caseId, "MANIFEST.txt", c);
        _clock.UtcNow = Start.AddMinutes(3);
        var idd = await UploadAsync(database, caseId, @"..\..\Windows\memory.dmp", d);
        _clock.UtcNow = Start.AddMinutes(10);

        var staged = await Cases(database).StageEvidencePackageAsync(caseId, null, " Outside counsel (Smith LLP) ", " SFTP ", "Litigation hold");
        (staged.Files, staged.Bytes).Should().Be((4, (long)(a.Length + b.Length + c.Length + d.Length)));
        staged.Ticket.Should().MatchRegex("^[0-9a-f]{32}$", "a random ticket, nothing picked or typed");
        var (zip, package) = await DownloadAsync(Evidence(database), staged.Ticket);

        var entries = Unzip(zip);
        entries.Keys.Should().Equal(["notes.txt", "NOTES (2).txt", "MANIFEST (2).txt", "memory.dmp", "MANIFEST.txt"],
            "base names only, none the same as another's or the manifest's, ignoring case, and the manifest last");
        Sha(entries["notes.txt"]).Should().Be(Sha(a));
        Sha(entries["NOTES (2).txt"]).Should().Be(Sha(b));
        Sha(entries["MANIFEST (2).txt"]).Should().Be(Sha(c));
        entries["memory.dmp"].Should().Equal(d);

        var manifest = Encoding.UTF8.GetString(entries["MANIFEST.txt"]);
        manifest.Should().Contain($"Case: {package.CaseNumber}").And.Contain("For: Outside counsel (Smith LLP)").And.Contain("Method: SFTP")
            .And.Contain("Purpose: Litigation hold").And.Contain("Files: 4");
        foreach (var x in new[] { a, b, c, d }) manifest.Should().Contain($"SHA-256: {Sha(x)}");
        manifest.Should().Contain(@"Original name: ..\..\Windows\memory.dmp").And.Contain("Size: 300,000 bytes")
            .And.Contain("Collected: 2026-10-18 04:00:00 UTC").And.Contain("Collected from: WKS-0142").And.Contain("Collected by: J. Rivera")
            .And.Contain("Uploaded: 2026-10-18 09:00:00 UTC by ic1").And.Contain("Uploaded by ic1");

        // One "Transferred" per file, after the bytes, naming the package and the hand-over.
        var transfers = await TransfersAsync(database);
        transfers.Select(t => t.EvidenceId).Should().BeEquivalentTo([ida, idb, idc, idd]);
        transfers.Should().AllSatisfy(t =>
        {
            t.Actor.Should().Be("ic1");
            t.Details.Should().Contain(package.FileName).And.Contain("To Outside counsel (Smith LLP) via SFTP. Purpose: Litigation hold");
        });
        // CAP-12 review: begun before the first byte (each file, and the package's entry with its id and the hand-over), then
        // sent in full, with the SHA-256 of the zip as sent and of its manifest; both in the chain, none through IAuditWriter.
        (await CustodyAsync(database, package.Id)).Where(c => c.Action == EvidenceService.PackageBegunAction).Select(c => c.EvidenceId)
            .Should().BeEquivalentTo([ida, idb, idc, idd]);
        var trail = await PackageAuditAsync(database, package.Id);
        trail.Should().HaveCount(2);
        trail[0].Should().StartWith($"Began sending evidence package {package.FileName} (id {package.Id})").And.Contain("4 evidence files")
            .And.Contain("Purpose: Litigation hold").And.Contain($"notes.txt (sha256 {Sha(a)})");
        trail[1].Should().StartWith("Sent evidence package").And.Contain("in full").And.Contain($"Package SHA-256 {Sha(zip)}")
            .And.Contain($"MANIFEST.txt SHA-256 {Sha(entries["MANIFEST.txt"])}").And.Contain("Purpose: Litigation hold");
        _audit.Entries.Should().BeEmpty();
        await using var ctx = database.NewContext();
        _hasher.VerifyChain(await ctx.AuditLog.OrderBy(x => x.Sequence).ToListAsync()).IsValid.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_withdrawn_file_is_left_out_refused_by_name_and_stops_a_package_prepared_before(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var kept = await UploadAsync(database, caseId, "kept.log", Text("kept"));
        _clock.UtcNow = Start.AddMinutes(1);   // the package lists files in upload order
        var gone = await UploadAsync(database, caseId, "gone.log", Text("gone"));
        _clock.UtcNow = Start.AddMinutes(2);
        var late = await UploadAsync(database, caseId, "late.log", Text("late"));
        var cases = Cases(database);
        await cases.WithdrawEvidenceAsync(caseId, gone, "Belongs to another case");

        var staged = await cases.StageEvidencePackageAsync(caseId, null, "Insurer", null, "Claim");
        staged.Files.Should().Be(2, "every file that stands");
        var (zip, _) = await DownloadAsync(Evidence(database), staged.Ticket);
        Unzip(zip).Keys.Should().Equal("kept.log", "late.log", "MANIFEST.txt");

        var named = () => cases.StageEvidencePackageAsync(caseId, [kept, gone], "Insurer", null, "Claim");
        (await named.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("withdrawn");

        // Withdrawn after it was prepared: the download is refused, and the ticket is spent.
        var before = await cases.StageEvidencePackageAsync(caseId, [kept, late], "Insurer", null, "Claim");
        await cases.WithdrawEvidenceAsync(caseId, late, "Wrong case too");
        var open = () => Evidence(database).OpenPackageAsync(before.Ticket);
        (await open.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("withdrawn");
        await open.Should().ThrowAsync<NotFoundException>("a ticket is taken once");
        (await TransfersAsync(database)).Should().HaveCount(2, "only the first package was recorded");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_package_is_held_to_the_size_cap_and_a_ticket_to_its_owner_once_and_its_lifetime(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        _limits.CurrentValue.MaxUploadMB = 1;
        var big = await UploadAsync(database, caseId, "big.bin", RandomNumberGenerator.GetBytes(700_000));
        var small = await UploadAsync(database, caseId, "small.bin", RandomNumberGenerator.GetBytes(400_000));
        var cases = Cases(database);

        var tooBig = () => cases.StageEvidencePackageAsync(caseId, null, "Insurer", null, "Claim");
        (await tooBig.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().Contain("more than the 1 MB");
        var none = () => cases.StageEvidencePackageAsync(caseId, [], "Insurer", null, "Claim");
        await none.Should().ThrowAsync<ArgumentException>();
        var noPurpose = () => cases.StageEvidencePackageAsync(caseId, [big], "Insurer", null, " ");
        await noPurpose.Should().ThrowAsync<ArgumentException>();

        var staged = await cases.StageEvidencePackageAsync(caseId, [big], "Insurer", null, "Claim");
        var stagedSmall = await cases.StageEvidencePackageAsync(caseId, [small], "Insurer", null, "Claim");
        // The cap lowered after it was prepared: checked again as the download begins.
        _limits.CurrentValue.MaxUploadMB = 2;
        var both = await cases.StageEvidencePackageAsync(caseId, null, "Insurer", null, "Claim");
        _limits.CurrentValue.MaxUploadMB = 1;
        var lowered = () => Evidence(database).OpenPackageAsync(both.Ticket);
        await lowered.Should().ThrowAsync<ArgumentException>();
        var colleague = new TestCurrentUser { UserId = "ic2", RoleSet = [AppRole.IncidentCommander] };
        var notTheirs = () => Evidence(database, colleague).OpenPackageAsync(staged.Ticket);
        await notTheirs.Should().ThrowAsync<NotFoundException>("a ticket is its preparer's");
        (await DownloadAsync(Evidence(database), staged.Ticket)).Package.Files.Should().ContainSingle();
        _clock.UtcNow = Start + EvidencePackageTickets.Lifetime + TimeSpan.FromSeconds(1);
        var expired = () => Evidence(database).OpenPackageAsync(stagedSmall.Ticket);
        await expired.Should().ThrowAsync<NotFoundException>();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_restricted_cases_evidence_cant_be_packaged_by_someone_off_it_or_without_edit(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        await UploadAsync(database, caseId, "hr.msg", Text("secret"));
        await Cases(database).SetRestrictedAsync(caseId, true, "Insider matter");
        var outsider = new TestCurrentUser { UserId = "analyst-unrelated", RoleSet = [AppRole.Analyst] };
        var reader = new TestCurrentUser { UserId = "ic1", RoleSet = [AppRole.IncidentCommander], PermissionSet = [Permission.ViewCases, Permission.ViewRestricted] };

        var hidden = () => Cases(database, outsider).StageEvidencePackageAsync(caseId, null, "Press", null, "Story");
        (await hidden.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("not found");
        var noEdit = () => Cases(database, reader).StageEvidencePackageAsync(caseId, null, "Insurer", null, "Claim");
        await noEdit.Should().ThrowAsync<ForbiddenException>();

        // Prepared by someone cleared for it, whose clearance is then taken away: the download is refused.
        var cleared = new TestCurrentUser { UserId = "ic9", PermissionSet = [Permission.ViewCases, Permission.EditCases, Permission.ViewRestricted] };
        var staged = await Cases(database, cleared).StageEvidencePackageAsync(caseId, null, "Insurer", null, "Claim");
        var removed = new TestCurrentUser { UserId = "ic9", PermissionSet = [Permission.ViewCases, Permission.EditCases] };
        var open = () => Evidence(database, removed).OpenPackageAsync(staged.Ticket);
        (await open.Should().ThrowAsync<NotFoundException>()).Which.Message.Should().Contain("not found");
        (await TransfersAsync(database)).Should().BeEmpty();
    }

    private static void NoDirectory(byte[] sent)
    {
        sent.AsSpan().IndexOf("PK\u0005\u0006"u8).Should().Be(-1, "the zip's central directory never went out");
        var opens = () => { using var z = new ZipFile(new MemoryStream(sent)); };
        opens.Should().Throw<Exception>("a zip tool that reads the directory doesn't open it");
    }

    private static string Action(List<ChainOfCustodyEvent> custody, Guid file) =>
        custody.Where(c => c.EvidenceId == file && c.Action != EvidenceService.PackageBegunAction).Should().ContainSingle().Subject.Action;

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_download_cut_off_in_the_second_of_three_files_is_recorded_as_partial_as_far_as_it_got(string provider)
    {
        // CAP-12 review: a data-descriptor zip reads from its local headers without its directory, so what went out before
        // a cut reaches the recipient. The record says so: begun before the first byte, then how far each file got.
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var (a, b, c) = (RandomNumberGenerator.GetBytes(200_000), RandomNumberGenerator.GetBytes(200_000), RandomNumberGenerator.GetBytes(200_000));
        var one = await UploadAsync(database, caseId, "one.bin", a);
        _clock.UtcNow = Start.AddMinutes(1);
        var two = await UploadAsync(database, caseId, "two.bin", b);
        _clock.UtcNow = Start.AddMinutes(2);
        var three = await UploadAsync(database, caseId, "three.bin", c);
        var staged = await Cases(database).StageEvidencePackageAsync(caseId, null, "Insurer", null, "Claim");
        using var cut = new CancellationTokenSource();
        // Each file is opened twice (checked, then sent): the 4th open is the second file being sent.
        var svc = Evidence(database, store: new CutOff(Files(), onOpen: 4, afterBytes: 120_000, cut));

        var (whole, sent, package, log) = await SendAsync(svc, staged.Ticket, cut.Token);

        whole.Should().BeFalse();
        NoDirectory(sent);
        var recovered = Recover(sent);
        recovered.Select(r => r.Name).Should().Equal(["one.bin", "two.bin"], "what a recipient can read without the directory");
        (recovered[0].Whole, recovered[0].Bytes).Should().Be((true, recovered[0].Bytes));
        recovered[0].Bytes.Should().Equal(a, "the first file arrives whole");
        recovered[1].Whole.Should().BeFalse();
        recovered[1].Bytes.Should().Equal(b.Take(recovered[1].Bytes.Length), "and a part of the second");

        var custody = await CustodyAsync(database, package.Id);
        custody.Where(x => x.Action == EvidenceService.PackageBegunAction).Select(x => x.EvidenceId).Should().BeEquivalentTo([one, two, three]);
        Action(custody, one).Should().Be(EvidenceService.PackageSentAction);
        Action(custody, two).Should().Be(EvidenceService.PackagePartlyAction);
        Action(custody, three).Should().Be(EvidenceService.PackageNotSentAction);
        var trail = await PackageAuditAsync(database, package.Id);
        trail.Should().HaveCount(2);
        trail[0].Should().StartWith("Began sending");
        trail[1].Should().Contain("stopped after 1 of 3 files (the download was cancelled or cut off)").And.Contain("Sent in full: one.bin.")
            .And.Contain("Sent in part: two.bin.").And.Contain("Not sent: three.bin.").And.Contain("MANIFEST.txt wasn't sent in full");
        log.Entries.Should().ContainSingle(e => e.Level == LogLevel.Warning).Which.Message.Should()
            .Contain("stopped after 1 of 3 files").And.Contain("recorded as partial");
        await using var ctx = database.NewContext();
        _hasher.VerifyChain(await ctx.AuditLog.OrderBy(x => x.Sequence).ToListAsync()).IsValid.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_file_that_no_longer_matches_its_record_is_never_sent_and_the_record_says_so(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var a = RandomNumberGenerator.GetBytes(200_000);
        var one = await UploadAsync(database, caseId, "one.bin", a);
        _clock.UtcNow = Start.AddMinutes(1);
        var two = await UploadAsync(database, caseId, "two.bin", RandomNumberGenerator.GetBytes(200_000));
        _clock.UtcNow = Start.AddMinutes(2);
        var three = await UploadAsync(database, caseId, "three.bin", RandomNumberGenerator.GetBytes(1000));
        // A stored file changed outside CaseBook.
        await using (var ctx = database.NewContext())
        {
            var path = (await ctx.Evidence.AsNoTracking().SingleAsync(e => e.Id == two)).StoragePath;
            await File.WriteAllBytesAsync(Path.Combine(_dir, "store", path), RandomNumberGenerator.GetBytes(200_000));
        }
        var staged = await Cases(database).StageEvidencePackageAsync(caseId, null, "Insurer", null, "Claim");

        var (whole, sent, package, _) = await SendAsync(Evidence(database), staged.Ticket);

        whole.Should().BeFalse();
        NoDirectory(sent);
        var recovered = Recover(sent);
        recovered.Should().ContainSingle("checked before any of it went out, the second file isn't in the zip at all");
        recovered[0].Bytes.Should().Equal(a);
        var custody = await CustodyAsync(database, package.Id);
        Action(custody, one).Should().Be(EvidenceService.PackageSentAction);
        custody.Single(x => x.EvidenceId == two && x.Action == EvidenceService.PackageNotSentAction).Details.Should().Contain("didn't match");
        Action(custody, three).Should().Be(EvidenceService.PackageNotSentAction);
        (await PackageAuditAsync(database, package.Id))[1].Should().Contain("(a file didn't match its recorded SHA-256)")
            .And.Contain("Not sent: two.bin, three.bin.").And.Contain("Not matching their recorded SHA-256: two.bin.");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_file_that_grows_between_its_check_and_its_send_is_recorded_as_sent_and_not_matching(string provider /* CAP-12 review */)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var one = await UploadAsync(database, caseId, "one.bin", RandomNumberGenerator.GetBytes(50_000));
        _clock.UtcNow = Start.AddMinutes(1);
        var two = await UploadAsync(database, caseId, "two.bin", RandomNumberGenerator.GetBytes(50_000));
        var staged = await Cases(database).StageEvidencePackageAsync(caseId, null, "Insurer", null, "Claim");

        // The second file checks out, then has a byte more by the time it's sent (its 4th open: each file is checked, then sent).
        var (whole, sent, package, _) = await SendAsync(Evidence(database, store: new Grows(Files(), onOpen: 4)), staged.Ticket);

        whole.Should().BeFalse();
        NoDirectory(sent);
        var custody = await CustodyAsync(database, package.Id);
        (Action(custody, one), Action(custody, two)).Should().Be((EvidenceService.PackageSentAction, EvidenceService.PackageSentNotMatchingAction),
            "every byte of it went out, so it's sent and not matching, not 'partly sent'");
        (await PackageAuditAsync(database, package.Id))[1].Should().Contain("Not matching their recorded SHA-256: two.bin.");
    }

    // A store whose n-th opened file has one byte more than was stored.
    private sealed class Grows(IEvidenceStore inner, int onOpen) : IEvidenceStore
    {
        private int _opened;
        public Task<StoredEvidence> SaveAsync(Guid caseId, Stream content, CancellationToken ct = default) => inner.SaveAsync(caseId, content, ct);

        public async Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default)
        {
            var s = await inner.OpenReadAsync(storagePath, ct);
            if (++_opened != onOpen) return s;
            var bytes = new MemoryStream();
            await using (s) await s.CopyToAsync(bytes, ct);
            bytes.WriteByte(0x5A);
            bytes.Position = 0;
            return bytes;
        }
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_store_or_key_outage_part_way_records_how_far_the_package_got(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var one = await UploadAsync(database, caseId, "one.bin", RandomNumberGenerator.GetBytes(200_000));
        _clock.UtcNow = Start.AddMinutes(1);
        var two = await UploadAsync(database, caseId, "two.bin", RandomNumberGenerator.GetBytes(200_000));
        var cases = Cases(database);

        async Task<(EvidencePackage Package, byte[] Sent)> FailingAsync(IEvidenceStore store)
        {
            var staged = await cases.StageEvidencePackageAsync(caseId, null, "Insurer", null, "Claim");
            var (whole, sent, package, _) = await SendAsync(Evidence(database, store: store), staged.Ticket);
            whole.Should().BeFalse();
            NoDirectory(sent);
            return (package, sent);
        }

        // The share drops part-way through sending the second file (its 4th open: each file is checked, then sent).
        var (dropped, _) = await FailingAsync(new Outage(Files(), failOnOpen: 4, afterBytes: 50_000, new IOException("The network path was not found.")));
        var custody = await CustodyAsync(database, dropped.Id);
        (Action(custody, one), Action(custody, two)).Should().Be((EvidenceService.PackageSentAction, EvidenceService.PackagePartlyAction));
        (await PackageAuditAsync(database, dropped.Id))[1].Should().Contain("(the evidence store or the connection failed)");

        // The evidence key goes away (ADR 0017) as the second file is checked: none of it goes out.
        var (keyless, sent) = await FailingAsync(new Outage(Files(), failOnOpen: 3, afterBytes: 0,
            new EvidenceKeyUnavailableException("The evidence key isn't available on this server.")));
        custody = await CustodyAsync(database, keyless.Id);
        (Action(custody, one), Action(custody, two)).Should().Be((EvidenceService.PackageSentAction, EvidenceService.PackageNotSentAction));
        Recover(sent).Select(r => r.Name).Should().Equal("one.bin");
        (await PackageAuditAsync(database, keyless.Id))[1].Should().Contain("(the evidence key wasn't available)");
        _audit.Entries.Should().BeEmpty("the record is written with the custody, not through IAuditWriter");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Custody_and_its_audit_entry_are_written_together_and_the_log_says_what_was_recorded(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        await UploadAsync(database, caseId, "one.bin", RandomNumberGenerator.GetBytes(50_000));
        _clock.UtcNow = Start.AddMinutes(1);
        await UploadAsync(database, caseId, "two.bin", RandomNumberGenerator.GetBytes(50_000));
        var cases = Cases(database);
        async Task<EvidencePackage> OpenPackageAsync() =>
            await Evidence(database).OpenPackageAsync((await cases.StageEvidencePackageAsync(caseId, null, "Insurer", null, "Claim")).Ticket);

        // An IAuditWriter that fails changes nothing: the package's record doesn't go through it.
        var svc = Evidence(database, audit: new ThrowingAudit());
        var (zip, sentWhole) = await DownloadAsync(svc, (await cases.StageEvidencePackageAsync(caseId, null, "Insurer", null, "Claim")).Ticket);
        Unzip(zip).Should().HaveCount(3);
        (await CustodyAsync(database, sentWhole.Id)).Count(c => c.Action == EvidenceService.PackageSentAction).Should().Be(2);
        (await PackageAuditAsync(database, sentWhole.Id)).Should().HaveCount(2);

        // The start can't be recorded: nothing of it is (no custody without its entry), and nothing would be sent.
        var unbegun = await OpenPackageAsync();
        _failing.FailNext = 1;
        var begin = () => Evidence(database).RecordPackageBegunAsync(unbegun);
        await begin.Should().ThrowAsync<InvalidOperationException>();
        (await CustodyAsync(database, unbegun.Id)).Should().BeEmpty();
        (await PackageAuditAsync(database, unbegun.Id)).Should().BeEmpty();

        // Sent in full, but its completion can't be recorded: the zip's directory is held back, and it's recorded as
        // stopped with every file sent (they can be read without the directory).
        var stopped = await OpenPackageAsync();
        await Evidence(database).RecordPackageBegunAsync(stopped);
        _failing.FailNext = 1;
        var log = new ListLogger();
        using (var output = new MemoryStream())
        {
            (await EvidencePackageEndpoints.SendAsync(stopped, Evidence(database).ManifestOf(stopped), Evidence(database), log, output, default))
                .Should().BeFalse();
            NoDirectory(output.ToArray());
            Recover(output.ToArray()).Select(r => r.Name).Should().Equal("one.bin", "two.bin", "MANIFEST.txt");
        }
        (await CustodyAsync(database, stopped.Id)).Where(c => c.Action != EvidenceService.PackageBegunAction).Select(c => c.Action)
            .Should().Equal(EvidenceService.PackageSentAction, EvidenceService.PackageSentAction);
        (await PackageAuditAsync(database, stopped.Id))[1].Should().Contain("stopped after 2 of 2 files (its completion couldn't be recorded)");
        log.Entries.Should().ContainSingle().Which.Should().Match<(LogLevel Level, string Message)>(e =>
            e.Level == LogLevel.Warning && e.Message.Contains("recorded as partial", StringComparison.Ordinal));

        // Neither end can be recorded: the record is the start alone (read as partial), and the log says that, not "recorded".
        var unended = await OpenPackageAsync();
        await Evidence(database).RecordPackageBegunAsync(unended);
        _failing.FailNext = 2;
        log = new ListLogger();
        using (var output = new MemoryStream())
            (await EvidencePackageEndpoints.SendAsync(unended, Evidence(database).ManifestOf(unended), Evidence(database), log, output, default))
                .Should().BeFalse();
        (await CustodyAsync(database, unended.Id)).Select(c => c.Action).Should().OnlyContain(a => a == EvidenceService.PackageBegunAction)
            .And.HaveCount(2);
        (await PackageAuditAsync(database, unended.Id)).Should().ContainSingle().Which.Should().StartWith("Began sending");
        var said = log.Entries.Should().ContainSingle().Subject;
        said.Level.Should().Be(LogLevel.Error);
        said.Message.Should().Contain("couldn't be recorded: the record shows only that it began").And.NotContain("recorded as partial");
        await using var ctx = database.NewContext();
        _hasher.VerifyChain(await ctx.AuditLog.OrderBy(x => x.Sequence).ToListAsync()).IsValid.Should().BeTrue();
    }

    [Fact]
    public void Names_in_the_zip_are_base_names_that_never_collide()
    {
        EvidencePackage.EntryNames(["a.txt", "A.TXT", "dir/a.txt", @"C:\x\manifest.txt", "a (2).txt", "", "<>"])
            .Should().Equal("a.txt", "A (2).TXT", "a (3).txt", "manifest (2).txt", "a (2) (2).txt", "evidence.bin", "evidence (2).bin");
    }

    // A store that fails on the n-th file it opens, after a number of its bytes (0: as it opens).
    private sealed class Outage(IEvidenceStore inner, int failOnOpen, int afterBytes, Exception failure) : IEvidenceStore
    {
        private int _opened;
        public Task<StoredEvidence> SaveAsync(Guid caseId, Stream content, CancellationToken ct = default) => inner.SaveAsync(caseId, content, ct);

        public async Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default)
        {
            if (++_opened != failOnOpen) return await inner.OpenReadAsync(storagePath, ct);
            if (afterBytes == 0) throw failure;
            return new Failing(await inner.OpenReadAsync(storagePath, ct), afterBytes, failure);
        }

        private sealed class Failing(Stream inner, int after, Exception failure) : Stream
        {
            private long _read;
            public override int Read(byte[] buffer, int offset, int count)
            {
                if (_read >= after) throw failure;
                var n = inner.Read(buffer, offset, (int)Math.Min(count, after - _read));
                _read += n;
                return n;
            }
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (_read >= after) throw failure;
                var n = await inner.ReadAsync(buffer[..(int)Math.Min(buffer.Length, after - _read)], cancellationToken);
                _read += n;
                return n;
            }
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => inner.Length;
            public override long Position { get => _read; set => throw new NotSupportedException(); }
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            protected override void Dispose(bool disposing)
            {
                if (disposing) inner.Dispose();
                base.Dispose(disposing);
            }
        }
    }

    // A database that refuses the next saves (ahead of the audit chain, so its gate is never held).
    private sealed class FailingSaves : SaveChangesInterceptor
    {
        public int FailNext;

        public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
        {
            Refuse();
            return result;
        }

        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            Refuse();
            return ValueTask.FromResult(result);
        }

        private void Refuse()
        {
            if (FailNext <= 0) return;
            FailNext--;
            throw new InvalidOperationException("The database is down.");
        }
    }

    // A store whose n-th opened file cancels the download after a number of its bytes.
    private sealed class CutOff(IEvidenceStore inner, int onOpen, int afterBytes, CancellationTokenSource cut) : IEvidenceStore
    {
        private int _opened;
        public Task<StoredEvidence> SaveAsync(Guid caseId, Stream content, CancellationToken ct = default) => inner.SaveAsync(caseId, content, ct);

        public async Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default)
        {
            var s = await inner.OpenReadAsync(storagePath, ct);
            return ++_opened == onOpen ? new Cutting(s, afterBytes, cut) : s;
        }

        private sealed class Cutting(Stream inner, int after, CancellationTokenSource cut) : Stream
        {
            private long _read;
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (_read >= after) await cut.CancelAsync();
                cancellationToken.ThrowIfCancellationRequested();
                var n = await inner.ReadAsync(buffer[..(int)Math.Min(buffer.Length, after - _read)], cancellationToken);
                _read += n;
                return n;
            }
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => inner.Length;
            public override long Position { get => _read; set => throw new NotSupportedException(); }
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            protected override void Dispose(bool disposing)
            {
                if (disposing) inner.Dispose();
                base.Dispose(disposing);
            }
        }
    }

    private sealed class ListLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }

    private sealed class ThrowingAudit : IAuditWriter
    {
        public Task RecordAsync(AuditAction action, string entityType, string? entityId, string? caseNumber, string summary, CancellationToken ct = default) =>
            throw new InvalidOperationException("The audit writer is down.");
    }

    private sealed class CapturingAudit : IAuditWriter
    {
        public List<(AuditAction Action, string EntityType, string? EntityId, string Summary)> Entries { get; } = [];
        public Task RecordAsync(AuditAction action, string entityType, string? entityId, string? caseNumber, string summary, CancellationToken ct = default)
        {
            Entries.Add((action, entityType, entityId, summary));
            return Task.CompletedTask;
        }
    }
}
