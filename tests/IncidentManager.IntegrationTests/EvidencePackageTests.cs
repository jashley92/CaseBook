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
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-12: a case's evidence packaged for hand-over: one zip with the password "infected" holding the files picked (every
/// file that stands by default; never a withdrawn one, CAP-21) under their base names, never colliding, and a MANIFEST.txt.
/// Each file's bytes match its recorded SHA-256. Once the whole package is written, each file gets a "Transferred" custody
/// event and the audit trail one entry naming the package and its SHA-256; a store outage part-way, a file that no longer
/// matches, or a record that can't be written leaves no record and no zip that opens. The size cap, the single-use ticket
/// and need-to-know hold. On both providers.
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

    public static TheoryData<string> Providers => TestDatabase.Providers;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private FileEvidenceStore Files() => new(Options.Create(new EvidenceStoreOptions { RootPath = Path.Combine(_dir, "store") }));

    private EvidenceService Evidence(TestDatabase db, TestCurrentUser? user = null, IEvidenceStore? store = null) =>
        new(db.Factory(), store ?? Files(), user ?? _user, _clock, _audit, _limits, packages: _tickets);

    private CaseService Cases(TestDatabase db, TestCurrentUser? user = null) =>
        new(db.Factory(), user ?? _user, _clock, new CaseNumberGenerator(db.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
            evidenceLimits: _limits, evidencePackages: _tickets);

    private async Task<(TestDatabase Db, Guid CaseId)> OpenAsync(string provider)
    {
        var db = TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
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

    // What the endpoint does once the ticket is taken: write the zip, recording it before its last bytes.
    private static async Task<(byte[] Zip, EvidencePackage Package)> DownloadAsync(EvidenceService svc, string ticket)
    {
        var package = await svc.OpenPackageAsync(ticket);
        using var output = new MemoryStream();
        await EvidencePackageWriter.WriteAsync(package, svc.ManifestOf(package), svc.OpenPackagedFileAsync, output,
            (sha, manifestSha) => svc.RecordPackageAsync(package, sha, manifestSha), default);
        return (output.ToArray(), package);
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
        // One audit entry naming the package, with the SHA-256 of the zip as sent and of its manifest.
        var entry = _audit.Entries.Should().ContainSingle().Subject;
        (entry.Action, entry.EntityType, entry.EntityId).Should().Be((AuditAction.EvidenceTransferred, "EvidencePackage", package.Id.ToString()));
        entry.Summary.Should().Contain("4 evidence files").And.Contain($"Package SHA-256 {Sha(zip)}")
            .And.Contain($"MANIFEST.txt SHA-256 {Sha(entries["MANIFEST.txt"])}").And.Contain("Purpose: Litigation hold");
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

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_outage_part_way_or_a_file_that_no_longer_matches_records_nothing_and_leaves_no_zip_that_opens(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        await UploadAsync(database, caseId, "one.bin", RandomNumberGenerator.GetBytes(200_000));
        var two = await UploadAsync(database, caseId, "two.bin", RandomNumberGenerator.GetBytes(200_000));
        var cases = Cases(database);

        async Task<byte[]> FailingAsync(IEvidenceStore store, Type expected, Func<EvidenceService, EvidencePackage, string, string, Task>? record = null)
        {
            var staged = await cases.StageEvidencePackageAsync(caseId, null, "Insurer", null, "Claim");
            var svc = Evidence(database, store: store);
            var package = await svc.OpenPackageAsync(staged.Ticket);
            using var output = new MemoryStream();
            var write = () => EvidencePackageWriter.WriteAsync(package, svc.ManifestOf(package), svc.OpenPackagedFileAsync, output,
                (sha, manifestSha) => record is null ? svc.RecordPackageAsync(package, sha, manifestSha) : record(svc, package, sha, manifestSha), default);
            (await write.Should().ThrowAsync<Exception>()).Which.Should().BeOfType(expected);
            return output.ToArray();
        }

        void NoZip(byte[] sent)
        {
            sent.AsSpan().IndexOf("PK\u0005\u0006"u8).Should().Be(-1, "the zip's central directory never went out");
            var opens = () => { using var z = new ZipFile(new MemoryStream(sent)); };
            opens.Should().Throw<Exception>();
        }

        // The share drops part-way through the second file.
        NoZip(await FailingAsync(new Outage(Files(), failOnOpen: 2, afterBytes: 50_000, new IOException("The network path was not found.")), typeof(IOException)));
        // The evidence key goes away (ADR 0017) as the second file opens.
        NoZip(await FailingAsync(new Outage(Files(), failOnOpen: 2, afterBytes: 0,
            new EvidenceKeyUnavailableException("The evidence key isn't available on this server.")), typeof(EvidenceKeyUnavailableException)));
        // The record itself can't be written: the directory is held back, so the zip doesn't open either.
        NoZip(await FailingAsync(Files(), typeof(InvalidOperationException), (_, _, _, _) => throw new InvalidOperationException("The database is down.")));
        (await TransfersAsync(database)).Should().BeEmpty();
        _audit.Entries.Should().BeEmpty();

        // A stored file changed outside CaseBook: its bytes don't match its record, so the package stops.
        await using (var ctx = database.NewContext())
        {
            var path = (await ctx.Evidence.AsNoTracking().SingleAsync(e => e.Id == two)).StoragePath;
            await File.WriteAllBytesAsync(Path.Combine(_dir, "store", path), RandomNumberGenerator.GetBytes(200_000));
        }
        NoZip(await FailingAsync(Files(), typeof(InvalidDataException)));
        (await TransfersAsync(database)).Should().BeEmpty("no custody event claims a transfer that didn't happen");
        _audit.Entries.Should().BeEmpty();
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
