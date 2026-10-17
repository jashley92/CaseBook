using System.Security.Cryptography;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Common;
using IncidentManager.Application.Evidence;
using IncidentManager.Application.Integrity;
using IncidentManager.Application.Security;
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
/// PROD-55/56: the administrator's limits on evidence (largest file, total, free space to keep) refuse an upload before a
/// byte is stored, on every path; a large file uploads in parts and is recorded exactly as an in-page upload is, through
/// retries, repeats, a half-written part, a damaged write, a withdrawn permission and abandonment; and a store that can't
/// be reached is one finding, not every file missing. On both providers.
/// </summary>
public sealed class EvidenceStorageTests : IDisposable
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 17, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.IncidentCommander] };
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-evidence-storage", Guid.NewGuid().ToString("N"));
    private readonly TestOptionsMonitor<EvidenceStorageOptions> _limits = new(new EvidenceStorageOptions { MinFreeSpaceGB = 0 });
    private readonly EvidenceUploadSessions _uploads = new();

    public static TheoryData<string> Providers => TestDatabase.Providers;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private const int Part = EvidenceUploadSessions.PartBytes;

    private FileEvidenceStore Files() => new(Options.Create(new EvidenceStoreOptions { RootPath = Path.Combine(_dir, "store") }));

    private EvidenceService Service(TestDatabase db, IEvidenceStore store, TestCurrentUser? user = null) =>
        new(db.Factory(), store, user ?? _user, _clock, new NoOpAuditWriter(), _limits, _uploads);

    private async Task<(TestDatabase Db, Guid CaseId)> OpenAsync(string provider)
    {
        var db = TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
        await using var ctx = db.NewContext();
        await DevDataSeeder.SeedAsync(ctx, _clock);
        return (db, (await ctx.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id);
    }

    private string[] StoredFiles() =>
        Directory.Exists(Path.Combine(_dir, "store"))
            ? Directory.GetFiles(Path.Combine(_dir, "store"), "*", SearchOption.AllDirectories)
                .Where(f => !Path.GetFileName(f).StartsWith(".probe-", StringComparison.Ordinal)).ToArray()
            : [];

    private static string Sha(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();

    // ---- PROD-55: the limits ----

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_file_over_the_largest_size_is_refused_before_a_byte_is_stored(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        _limits.CurrentValue = new EvidenceStorageOptions { MaxUploadMB = 1, MinFreeSpaceGB = 0 };
        var svc = Service(database, Files());

        var declared = () => svc.UploadAsync(caseId, "dump.bin", "", new MemoryStream(new byte[2 * 1024 * 1024]), null, 2 * 1024 * 1024);
        (await declared.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().Contain("largest file CaseBook takes is 1 MB");

        // A size declared small doesn't let more through: the stream is held to the limit and nothing is kept.
        var lied = () => svc.UploadAsync(caseId, "dump.bin", "", new MemoryStream(new byte[2 * 1024 * 1024]), null, 10);
        await lied.Should().ThrowAsync<ArgumentException>();
        var parts = () => svc.BeginUploadAsync(caseId, "dump.bin", "", 2 * 1024 * 1024, null);
        await parts.Should().ThrowAsync<ArgumentException>();
        StoredFiles().Should().BeEmpty();
        await using var ctx = database.NewContext();
        (await ctx.Evidence.CountAsync(e => e.OriginalFileName == "dump.bin")).Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_total_limit_and_the_free_space_to_keep_refuse_what_would_pass_them(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        const long gib = 1024L * 1024 * 1024;
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            // A record standing for a large file already stored: 100 bytes short of 1 GB.
            raw.Evidence.Add(new Evidence
            {
                CaseId = caseId, OriginalFileName = "big.raw", ContentType = "application/octet-stream", SizeBytes = gib - 100,
                Sha256 = new string('a', 64), StoragePath = "x/y.bin", CreatedBy = "seed", CreatedAtUtc = _clock.UtcNow,
            });
            await raw.SaveChangesAsync();
        }
        _limits.CurrentValue = new EvidenceStorageOptions { StorageQuotaGB = 1, MinFreeSpaceGB = 0 };
        var svc = Service(database, Files());
        var over = () => svc.UploadAsync(caseId, "over.txt", "", new MemoryStream(new byte[200]), null, 200);
        (await over.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().Contain("past its 1 GB limit");
        (await svc.UploadAsync(caseId, "fits.txt", "", new MemoryStream(new byte[50]), null, 50)).SizeBytes.Should().Be(50);
        (await svc.StorageUseAsync()).NearQuota.Should().BeTrue();

        // Free space: an upload must leave the reserve on the store's volume.
        _limits.CurrentValue = new EvidenceStorageOptions { MinFreeSpaceGB = 10 };
        var tight = Service(database, new FreeSpaceStore(Files(), 10 * gib + 100));
        var noRoom = () => tight.UploadAsync(caseId, "c.txt", "", new MemoryStream(new byte[200]), null, 200);
        (await noRoom.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().Contain("less than 10 GB free");
        (await tight.UploadAsync(caseId, "d.txt", "", new MemoryStream(new byte[50]), null, 50)).SizeBytes.Should().Be(50);
    }

    [Fact]
    public void Sizes_read_the_same_everywhere()
    {
        EvidenceRoom.Size(10).Should().Be("1 KB");
        EvidenceRoom.Size(4_404_019).Should().Be("4.2 MB");
        EvidenceRoom.Size(1L << 30).Should().Be("1 GB");
        new EvidenceStorageOptions { MaxUploadMB = 65_536 }.MaxUploadBytes.Should().Be(64L << 30, "no overflow at the largest setting");
        new EvidenceStorageOptions { StorageQuotaGB = 1_000_000 }.QuotaBytes.Should().Be(1_000_000L << 30);
        new EvidenceStorageOptions { StorageQuotaGB = 0 }.QuotaBytes.Should().BeNull();

        // Diagnostics' meter: the share of the limit used, the 90 % warning, and no share without a limit.
        new EvidenceStorageUse(150, 1000, null, 0).QuotaShare.Should().BeApproximately(0.15, 1e-9);
        new EvidenceStorageUse(900, 1000, null, 0).NearQuota.Should().BeTrue();
        new EvidenceStorageUse(899, 1000, null, 0).NearQuota.Should().BeFalse();
        new EvidenceStorageUse(1200, 1000, null, 0).QuotaShare.Should().BeGreaterThan(1, "over the limit reads as over, not capped");
        new EvidenceStorageUse(150, null, null, 0).QuotaShare.Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_file_that_fits_isnt_refused_once_its_bytes_are_on_the_store(string provider)
    {
        // Review finding 2: the checks after storing (and at a large upload's completion) took the file's size off a free
        // space that already reflected it, so a file that fitted was refused and its parts deleted.
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        const long gib = 1024L * 1024 * 1024;
        _limits.CurrentValue = new EvidenceStorageOptions { MinFreeSpaceGB = 10 };
        var bytes = Random(2 * Part + 77);

        var inPage = Service(database, new FreeSpaceStore(Files(), 10 * gib + bytes.Length, shrinks: true));
        (await inPage.UploadAsync(caseId, "edge.bin", "", new MemoryStream(bytes), null, bytes.Length)).SizeBytes.Should().Be(bytes.Length,
            "exactly the reserve is left: it fits");
        var undeclared = Service(database, new FreeSpaceStore(Files(), 10 * gib + bytes.Length, shrinks: true));
        (await undeclared.UploadAsync(caseId, "edge2.bin", "", new MemoryStream(bytes), null)).SizeBytes.Should().Be(bytes.Length,
            "its size known only once stored");

        var parts = Service(database, new FreeSpaceStore(Files(), 10 * gib + bytes.Length, shrinks: true));
        var started = await parts.BeginUploadAsync(caseId, "edge.dmp", "", bytes.Length, null);
        await SendAllAsync(parts, started, bytes);
        (await parts.CompleteUploadAsync(started.Id)).Sha256.Should().Be(Sha(bytes));

        var tooBig = Service(database, new FreeSpaceStore(Files(), 10 * gib + bytes.Length - 1, shrinks: true));
        var refused = () => tooBig.BeginUploadAsync(caseId, "over.dmp", "", bytes.Length, null);
        await refused.Should().ThrowAsync<ArgumentException>("one byte short is still refused up front");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_part_retried_after_a_failed_write_must_be_the_same_bytes(string provider)
    {
        // Review finding 4: a retry is written again at the same offset, so its chunks are sealed again under the same file
        // key and nonces. With the same bytes that's harmless; with different ones (the file changed under the browser) it
        // would leak them, so the upload is stopped instead.
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var flaky = new FlakyStore(Files());
        var svc = Service(database, flaky);
        var bytes = Random(2 * Part + 10);

        var same = await svc.BeginUploadAsync(caseId, "same.bin", "", bytes.Length, null);
        await svc.AppendPartAsync(same.Id, 0, bytes.AsMemory(0, Part));
        flaky.FailNext = true;
        var cut = () => svc.AppendPartAsync(same.Id, 1, bytes.AsMemory(Part, Part));
        await cut.Should().ThrowAsync<IOException>();
        await svc.AppendPartAsync(same.Id, 1, bytes.AsMemory(Part, Part));   // the same bytes again: fine
        await svc.AppendPartAsync(same.Id, 2, bytes.AsMemory(2 * Part, 10));
        (await svc.CompleteUploadAsync(same.Id)).Sha256.Should().Be(Sha(bytes));

        var changed = await svc.BeginUploadAsync(caseId, "changed.bin", "", bytes.Length, null);
        await svc.AppendPartAsync(changed.Id, 0, bytes.AsMemory(0, Part));
        flaky.FailNext = true;
        await ((Func<Task>)(() => svc.AppendPartAsync(changed.Id, 1, bytes.AsMemory(Part, Part)))).Should().ThrowAsync<IOException>();
        var edited = bytes.AsSpan(Part, Part).ToArray();
        edited[0] ^= 0xFF;
        var retry = () => svc.AppendPartAsync(changed.Id, 1, edited);
        (await retry.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("changed while it was uploading");
        var later = () => svc.AppendPartAsync(changed.Id, 1, bytes.AsMemory(Part, Part));
        await later.Should().ThrowAsync<InvalidOperationException>("the upload is over");
        Directory.GetFiles(Path.Combine(_dir, "store", ".incoming")).Should().BeEmpty("its parts are deleted");
    }

    /// <summary>A store whose next part write fails half-way (the request cut off mid-write).</summary>
    private sealed class FlakyStore(IEvidenceStore inner) : IEvidenceStore
    {
        public bool FailNext { get; set; }
        public Task<StoredEvidence> SaveAsync(Guid caseId, Stream content, CancellationToken ct = default) => inner.SaveAsync(caseId, content, ct);
        public Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default) => inner.OpenReadAsync(storagePath, ct);
        public Task DiscardUnrecordedAsync(string storagePath) => inner.DiscardUnrecordedAsync(storagePath);
        public Task<long?> FreeBytesAsync(CancellationToken ct = default) => Task.FromResult<long?>(null);
        public Task<string> BeginIncomingAsync(CancellationToken ct = default) => inner.BeginIncomingAsync(ct);
        public async Task AppendIncomingAsync(string incoming, long offset, ReadOnlyMemory<byte> bytes, CancellationToken ct = default)
        {
            if (!FailNext)
            {
                await inner.AppendIncomingAsync(incoming, offset, bytes, ct);
                return;
            }
            FailNext = false;
            await inner.AppendIncomingAsync(incoming, offset, bytes[..(bytes.Length / 2)], ct);
            throw new IOException("The connection was cut off mid-write.");
        }
        public Task<Stream> OpenIncomingAsync(string incoming, CancellationToken ct = default) => inner.OpenIncomingAsync(incoming, ct);
        public Task FinishIncomingAsync(string incoming, long size, CancellationToken ct = default) => inner.FinishIncomingAsync(incoming, size, ct);
        public Task<StoredEvidence> CommitIncomingAsync(string incoming, Guid caseId, string sha256, long size, CancellationToken ct = default) =>
            inner.CommitIncomingAsync(incoming, caseId, sha256, size, ct);
        public Task DiscardIncomingAsync(string incoming) => inner.DiscardIncomingAsync(incoming);
        public Task<int> ClearIncomingAsync(TimeSpan olderThan, CancellationToken ct = default) => inner.ClearIncomingAsync(olderThan, ct);
    }

    [Fact]
    public async Task The_store_reports_its_volume_size_with_its_free_space()
    {
        var store = Files();
        store.CreateIfNew();   // start-up makes a fresh store's folder
        var total = await store.TotalBytesAsync();
        var free = await store.FreeBytesAsync();
        total.Should().BeGreaterThan(0);
        free.Should().BeLessThanOrEqualTo(total!.Value);
    }

    // ---- PROD-56: uploading in parts ----

    private static byte[] Random(int size) => RandomNumberGenerator.GetBytes(size);

    private static async Task SendAllAsync(EvidenceService svc, EvidenceService.UploadStarted started, byte[] bytes)
    {
        for (var i = 0; i < started.Parts; i++)
            await svc.AppendPartAsync(started.Id, i, bytes.AsMemory(i * Part, Math.Min(Part, bytes.Length - i * Part)));
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_file_sent_in_parts_is_recorded_as_an_in_page_upload_is(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var svc = Service(database, Files());
        var bytes = Random(2 * Part + 1234);

        var started = await svc.BeginUploadAsync(caseId, "memory.dmp", "application/octet-stream", bytes.Length, "Host memory");
        started.Parts.Should().Be(3);
        started.PartBytes.Should().Be(Part);
        await SendAllAsync(svc, started, bytes);
        var recorded = await svc.CompleteUploadAsync(started.Id);

        recorded.SizeBytes.Should().Be(bytes.Length);
        recorded.Sha256.Should().Be(Sha(bytes));
        recorded.Description.Should().Be("Host memory");
        var (_, content) = await svc.OpenAsync(recorded.Id, recordDownload: false);
        await using (content)
        {
            using var copy = new MemoryStream();
            await content.CopyToAsync(copy);
            copy.ToArray().Should().Equal(bytes);
        }
        await using var ctx = database.NewContext();
        var custody = await ctx.Set<ChainOfCustodyEvent>().Where(c => c.EvidenceId == recorded.Id).ToListAsync();
        custody.Should().ContainSingle(c => c.Action == "Uploaded").Which.Details.Should().Be($"{bytes.Length} bytes; sha256={Sha(bytes)}");
        StoredFiles().Should().ContainSingle("the parts became the stored file; nothing is left in .incoming");
        (await svc.CompleteUploadAsync(started.Id)).Id.Should().Be(recorded.Id, "finishing twice answers with the same record");
        (await ctx.Evidence.CountAsync(e => e.OriginalFileName == "memory.dmp")).Should().Be(1);
        await svc.AbandonUploadAsync(started.Id);   // after it finished, nothing to do
        StoredFiles().Should().ContainSingle();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Parts_repeated_out_of_order_wrong_sized_or_half_written_are_handled(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var svc = Service(database, Files());
        var bytes = Random(2 * Part + 99);
        var started = await svc.BeginUploadAsync(caseId, "a.pcap", "", bytes.Length, null);

        (await svc.AppendPartAsync(started.Id, 0, bytes.AsMemory(0, Part))).Should().Be(Part);
        (await svc.AppendPartAsync(started.Id, 0, bytes.AsMemory(0, Part))).Should().Be(Part, "a repeat is acknowledged, not written twice");
        var early = () => svc.AppendPartAsync(started.Id, 2, bytes.AsMemory(2 * Part, 99));
        await early.Should().ThrowAsync<InvalidOperationException>();
        var wrong = () => svc.AppendPartAsync(started.Id, 1, bytes.AsMemory(Part, 10));
        await wrong.Should().ThrowAsync<ArgumentException>();
        var unfinished = () => svc.CompleteUploadAsync(started.Id);
        (await unfinished.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("missing parts");

        // A write that failed half-way left bytes past the last whole part: the next attempt cuts them off.
        var part = Directory.GetFiles(Path.Combine(_dir, "store", ".incoming"), "*.part").Single();
        await using (var fs = new FileStream(part, FileMode.Append)) await fs.WriteAsync(Random(5000));
        await svc.AppendPartAsync(started.Id, 1, bytes.AsMemory(Part, Part));
        await svc.AppendPartAsync(started.Id, 2, bytes.AsMemory(2 * Part, 99));
        (await svc.CompleteUploadAsync(started.Id)).Sha256.Should().Be(Sha(bytes));
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_write_damaged_on_its_way_to_the_store_is_caught_and_not_recorded(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var svc = Service(database, Files());
        var bytes = Random(Part + 10);
        var started = await svc.BeginUploadAsync(caseId, "b.bin", "", bytes.Length, null);
        await SendAllAsync(svc, started, bytes);

        var part = Directory.GetFiles(Path.Combine(_dir, "store", ".incoming"), "*.part").Single();
        await using (var fs = new FileStream(part, FileMode.Open)) { fs.Position = 100; fs.WriteByte(0x5A); }
        var complete = () => svc.CompleteUploadAsync(started.Id);
        (await complete.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().Contain("damaged");
        StoredFiles().Should().BeEmpty("the damaged parts are deleted, and nothing was stored");
        await using var ctx = database.NewContext();
        (await ctx.Evidence.CountAsync(e => e.OriginalFileName == "b.bin")).Should().Be(0);
        var again = () => svc.CompleteUploadAsync(started.Id);
        await again.Should().ThrowAsync<InvalidOperationException>();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Only_its_owner_can_touch_an_upload_and_a_withdrawn_permission_or_lowered_limit_stops_it(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var svc = Service(database, Files());
        var bytes = Random(Part + 5);
        var started = await svc.BeginUploadAsync(caseId, "c.bin", "", bytes.Length, null);

        var other = Service(database, Files(), new TestCurrentUser { UserId = "someone-else", RoleSet = [AppRole.IncidentCommander] });
        var theirs = () => other.AppendPartAsync(started.Id, 0, bytes.AsMemory(0, Part));
        await theirs.Should().ThrowAsync<NotFoundException>();
        await ((Func<Task>)(() => other.CompleteUploadAsync(started.Id))).Should().ThrowAsync<NotFoundException>();
        await ((Func<Task>)(() => other.AbandonUploadAsync(started.Id))).Should().ThrowAsync<NotFoundException>();

        await SendAllAsync(svc, started, bytes);
        _user.RoleSet = [AppRole.Manager];   // can see cases, not edit them
        var withdrawn = () => svc.CompleteUploadAsync(started.Id);
        await withdrawn.Should().ThrowAsync<ForbiddenException>();
        _user.RoleSet = [AppRole.IncidentCommander];

        _limits.CurrentValue = new EvidenceStorageOptions { MaxUploadMB = 1, MinFreeSpaceGB = 0 };
        var lowered = () => svc.CompleteUploadAsync(started.Id);
        await lowered.Should().ThrowAsync<ArgumentException>("the limits are checked again when it completes");
        _limits.CurrentValue = new EvidenceStorageOptions { MinFreeSpaceGB = 0 };
        (await svc.CompleteUploadAsync(started.Id)).Sha256.Should().Be(Sha(bytes));
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Uploads_in_progress_are_capped_and_abandoned_or_idle_ones_are_cleared(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var store = Files();
        var svc = Service(database, store);
        var ids = new List<string>();
        for (var i = 0; i < EvidenceUploadSessions.MaxPerUser; i++)
            ids.Add((await svc.BeginUploadAsync(caseId, $"f{i}.bin", "", Part * 2L, null)).Id);
        var fourth = () => svc.BeginUploadAsync(caseId, "f4.bin", "", Part * 2L, null);
        (await fourth.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().Contain("uploads in progress");

        await svc.AbandonUploadAsync(ids[0]);
        Directory.GetFiles(Path.Combine(_dir, "store", ".incoming")).Should().HaveCount(2, "the abandoned upload's parts are deleted");
        await svc.BeginUploadAsync(caseId, "f5.bin", "", Part * 2L, null);

        // A day later with nothing sent, every upload is dropped and its parts deleted; so are parts no upload holds.
        await File.WriteAllBytesAsync(Path.Combine(_dir, "store", ".incoming", new string('a', 32) + ".part"), [1, 2, 3]);
        var swept = await EvidenceService.SweepUploadsAsync(_uploads, store, _clock.UtcNow.Add(EvidenceUploadSessions.IdleLimit).AddMinutes(1),
            TimeSpan.Zero);
        swept.Should().BeGreaterThanOrEqualTo(4);
        Directory.GetFiles(Path.Combine(_dir, "store", ".incoming")).Should().BeEmpty();
        _uploads.InProgress.Should().Be(0);
        var gone = () => svc.AppendPartAsync(ids[1], 0, new byte[Part]);
        await gone.Should().ThrowAsync<NotFoundException>();
    }

    // ---- PROD-56: a store that can't be reached ----

    [Fact]
    public async Task The_probe_says_whether_the_store_can_be_written_and_read()
    {
        (await StoreVolume.ProbeAsync(Path.Combine(_dir, "ok"))).Should().BeNull();
        Directory.GetFiles(Path.Combine(_dir, "ok")).Should().BeEmpty("the probe cleans up after itself");
        Directory.CreateDirectory(_dir);
        var file = Path.Combine(_dir, "not-a-folder");
        await File.WriteAllTextAsync(file, "x");
        (await StoreVolume.ProbeAsync(Path.Combine(file, "store"))).Should().NotBeNull("a folder can't be made under a file");
        (await StoreVolume.FreeBytesAsync(Path.Combine(_dir, "ok"))).Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task A_store_that_held_evidence_and_vanished_is_reported_never_recreated_empty()
    {
        // Found on a UNC store: with the store's folder gone but the share answering, the probe recreated it empty and
        // said all was well, uploads went into the empty stand-in, and every download said its file was missing.
        var root = Path.Combine(_dir, "store");
        var fresh = Files();
        fresh.CreateIfNew();
        Directory.Exists(root).Should().BeTrue("a fresh store's folder is made at start-up");
        var stored = await fresh.SaveAsync(Guid.NewGuid(), new MemoryStream("sample"u8.ToArray()));
        Directory.Delete(root, recursive: true);

        (await fresh.ProbeAsync()).Should().Contain("isn't there", "after its first save the store knows it holds evidence");
        Directory.Exists(root).Should().BeFalse();

        var restarted = Files();   // a restart: start-up finds evidence recorded
        restarted.HoldsEvidence();
        restarted.CreateIfNew();
        Directory.Exists(root).Should().BeFalse("never recreated at start-up either");
        (await restarted.ProbeAsync()).Should().Contain("isn't there");
        var read = () => restarted.OpenReadAsync(stored.StoragePath);
        (await read.Should().ThrowAsync<EvidenceStoreUnreachableException>()).Which.Should().BeAssignableTo<IOException>(
            "one answer for every file, the store can't be reached (503), not this file missing (404)");
        var save = () => restarted.SaveAsync(Guid.NewGuid(), new MemoryStream("new"u8.ToArray()));
        await save.Should().ThrowAsync<EvidenceStoreUnreachableException>("nothing goes into an empty stand-in");
        var part = () => restarted.BeginIncomingAsync();
        await part.Should().ThrowAsync<EvidenceStoreUnreachableException>();
        Directory.Exists(root).Should().BeFalse();

        Directory.CreateDirectory(root);   // the share is back (here: empty, so the one file is missing, not the store)
        (await restarted.ProbeAsync()).Should().BeNull();
        var missing = () => restarted.OpenReadAsync(stored.StoragePath);
        (await missing.Should().ThrowAsync<IOException>()).Which.Should().NotBeOfType<EvidenceStoreUnreachableException>(
            "with the store there, a file that isn't is that file missing");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_unreachable_store_is_one_finding_and_earlier_findings_stand(string provider)
    {
        var (database, caseId) = await OpenAsync(provider);
        using var _ = database;
        var store = Files();
        var good = Service(database, store);
        var a = await good.UploadAsync(caseId, "a.txt", "", new MemoryStream("alpha"u8.ToArray()), null);
        await good.UploadAsync(caseId, "b.txt", "", new MemoryStream("bravo"u8.ToArray()), null);
        await File.WriteAllTextAsync(Path.Combine(_dir, "store", a.StoragePath), "tampered");

        var monitor = new EvidenceIntegrityMonitor();
        var alerts = new CountingAlerts();
        (await new EvidenceIntegrityVerifier(database.Factory(), store, _clock, monitor, alerts).VerifyAndTrackAsync())
            .Drifts.Should().ContainSingle(d => d.EvidenceId == a.Id);

        var down = new FreeSpaceStore(store, null, "the network path was not found");
        var unreachable = await new EvidenceIntegrityVerifier(database.Factory(), down, _clock, monitor, alerts).VerifyAndTrackAsync();
        unreachable.CheckedCount.Should().Be(0);
        unreachable.Drifts.Should().ContainSingle().Which.Kind.Should().Be(EvidenceDriftKind.StoreUnreachable);
        monitor.Current!.Drifts.Select(d => d.Kind).Should().BeEquivalentTo(
            [EvidenceDriftKind.HashMismatch, EvidenceDriftKind.StoreUnreachable], "the earlier finding stands; nothing was checked");
        (await new EvidenceIntegrityVerifier(database.Factory(), down, _clock, monitor, alerts).VerifyAndTrackAsync()).Should().NotBeNull();
        alerts.Count.Should().Be(2, "the mismatch once, the unreachable store once, however many runs it lasts");

        await new EvidenceIntegrityVerifier(database.Factory(), store, _clock, monitor, alerts).VerifyAndTrackAsync();
        monitor.Current.Drifts.Should().ContainSingle(d => d.EvidenceId == a.Id, "back in reach, only the real finding remains");
    }

    private sealed class CountingAlerts : IEvidenceIntegrityAlertNotifier
    {
        public int Count { get; private set; }
        public Task OnDriftDetectedAsync(EvidenceVerificationResult result, CancellationToken ct = default)
        {
            Count++;
            return Task.CompletedTask;
        }
    }

    /// <summary>A store that reports a given free space, or that can't be reached (a share that's down). With
    /// <paramref name="shrinks"/>, the free space goes down by every byte written, as a real disk's does.</summary>
    private sealed class FreeSpaceStore(IEvidenceStore inner, long? free, string? problem = null, bool shrinks = false) : IEvidenceStore
    {
        private long _written;
        public async Task<StoredEvidence> SaveAsync(Guid caseId, Stream content, CancellationToken ct = default)
        {
            var stored = await inner.SaveAsync(caseId, content, ct);
            Interlocked.Add(ref _written, stored.SizeBytes);
            return stored;
        }
        public Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default) => inner.OpenReadAsync(storagePath, ct);
        public Task DiscardUnrecordedAsync(string storagePath) => inner.DiscardUnrecordedAsync(storagePath);
        public Task<long?> FreeBytesAsync(CancellationToken ct = default) =>
            Task.FromResult(shrinks ? free - Interlocked.Read(ref _written) : free);
        public Task<string?> ProbeAsync(CancellationToken ct = default) => Task.FromResult(problem);
        public string Location => inner.Location;
        public Task<string> BeginIncomingAsync(CancellationToken ct = default) => inner.BeginIncomingAsync(ct);
        public async Task AppendIncomingAsync(string incoming, long offset, ReadOnlyMemory<byte> bytes, CancellationToken ct = default)
        {
            await inner.AppendIncomingAsync(incoming, offset, bytes, ct);
            Interlocked.Add(ref _written, bytes.Length);
        }
        public Task<Stream> OpenIncomingAsync(string incoming, CancellationToken ct = default) => inner.OpenIncomingAsync(incoming, ct);
        public Task<StoredEvidence> CommitIncomingAsync(string incoming, Guid caseId, string sha256, long size, CancellationToken ct = default) =>
            inner.CommitIncomingAsync(incoming, caseId, sha256, size, ct);
        public Task DiscardIncomingAsync(string incoming) => inner.DiscardIncomingAsync(incoming);
        public Task<int> ClearIncomingAsync(TimeSpan olderThan, CancellationToken ct = default) => inner.ClearIncomingAsync(olderThan, ct);
    }
}
