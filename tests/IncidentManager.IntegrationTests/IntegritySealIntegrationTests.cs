using IncidentManager.Domain.Enums;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Exercises the RSA-signed integrity seal end-to-end: sealing the chain head, verifying the seal,
/// and detecting history that is rewritten after sealing.
/// </summary>
public sealed class IntegritySealIntegrationTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] }; // admin/config writes assert Administer (F-23)
    private readonly string _workDir = Path.Combine(Path.GetTempPath(), "im-seal-tests", Guid.NewGuid().ToString("N"));
    private readonly RsaSealSigner _signer;
    private readonly FileSealStore _store;
    private readonly IntegrityMonitor _monitor = new();
    private readonly CapturingAlerts _alerts = new();

    public IntegritySealIntegrationTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _signer = new RsaSealSigner(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(_workDir, "k.pem"), AllowKeyGeneration = true }));
        _store = new FileSealStore(Options.Create(new SealSigningOptions { ExportPath = Path.Combine(_workDir, "seals") }));
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

    private IntegrityService NewService(AppDbContext db) =>
        new(NewFactory(), _hasher, _signer, _store, _user, _clock, _monitor, _alerts);

    /// <summary>Records each alarm so tests can assert it fired the right number of times.</summary>
    private sealed class CapturingAlerts : IIntegrityAlertNotifier
    {
        public List<ChainVerificationResult> Fired { get; } = new();
        public Task OnChainBrokenAsync(ChainVerificationResult result, CancellationToken ct = default)
        {
            Fired.Add(result);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task A_cases_audit_trail_keeps_the_entries_made_under_its_earlier_number(/* REV-01 */)
    {
        await using var db = NewContext();
        var cases = new IncidentManager.Application.Cases.CaseService(NewFactory(), _user, _clock, new CaseNumberGenerator(db),
            new IncidentManager.Application.Cases.CreateCaseValidator(), new NoOpCaseNotifications(),
            new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());
        var ce = await cases.CreateAsync(new IncidentManager.Application.Cases.CreateCaseRequest
        {
            DescriptiveName = "Odd Beaconing", Title = "Odd beaconing", Classification = null, Severity = Severity.Medium, Origin = CaseOrigin.InternalDetection
        });
        var intake = ce.CaseNumber;
        await cases.AddNoteAsync(ce.Id, "Seen on two hosts before promotion.");
        await cases.ReclassifyAsync(ce.Id, Classification.AdverseEvent, "Confirmed adverse event");
        var promoted = (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == ce.Id)).CaseNumber;
        promoted.Should().NotBe(intake);

        var svc = NewService(db);
        var trail = await svc.QueryAsync(new AuditQueryFilter { CaseNumber = promoted });
        trail.Select(a => a.CaseNumber).Should().Contain(intake, "the intake entries were saved under the Complex Event number")
            .And.Contain(promoted);
        trail.Should().Contain(a => a.EntityType == "AnalystNote");
        (await svc.AuditFacetsAsync(promoted)).EntityTypes.Should().Contain("AnalystNote");
        (await svc.RecentAsync(promoted)).Should().HaveCount(trail.Count);
    }

    [Fact]
    public async Task A_manual_seal_is_refused_over_a_chain_that_does_not_verify(/* REV-04 */)
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var old = await db.AuditLog.OrderBy(a => a.Sequence).Skip(1).FirstAsync();
        old.EntryHash = new string('0', 64);
        await db.SaveChangesAsync();
        var svc = NewService(db);

        var seal = async () => await svc.SealAsync();

        (await seal.Should().ThrowAsync<InvalidOperationException>()).WithMessage("No seal was recorded*");
        (await svc.RecentSealsAsync()).Should().BeEmpty();
        _alerts.Fired.Should().ContainSingle("the check behind the refusal raises the alarm like any other");
    }

    [Fact]
    public async Task Two_seals_in_the_same_second_each_keep_their_copy(/* REV-07 */)
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewService(db);

        await svc.SealAsync();
        await svc.SealAsync();   // same head, same clock second

        Directory.GetFiles(Path.Combine(_workDir, "seals")).Should().HaveCount(2);
    }

    [Fact]
    public async Task Seal_is_signed_exported_and_verifies_valid()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewService(db);

        var seal = await svc.SealAsync();

        seal.Should().NotBeNull();
        seal!.Signature.Should().NotBeNullOrEmpty();
        seal.Algorithm.Should().Be("RSASSA-PSS-SHA256");
        seal.KeyId.Should().Be(_signer.KeyId);

        // Exported out of band.
        Directory.GetFiles(Path.Combine(_workDir, "seals")).Should().ContainSingle();

        var result = await svc.VerifySealAsync(seal.Id);
        result.IsValid.Should().BeTrue();
        result.SignatureValid.Should().BeTrue();
        result.ChainMatches.Should().BeTrue();
    }

    [Fact]
    public async Task A_seal_made_while_the_chain_key_is_on_records_where_keying_starts_and_still_verifies(/* BUG-142 */)
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);   // plain-hashed history
        var head = await db.AuditLog.MaxAsync(a => a.Sequence);
        var keyed = new IntegrityService(NewFactory(), _hasher, _signer, _store, _user, _clock, _monitor, _alerts,
            chainKeys: new OneKey());

        var seal = (await keyed.SealAsync())!;
        seal.KeyedFromSequence.Should().Be(head + 1, "nothing is keyed yet; this server keys what comes next");
        (await keyed.VerifySealAsync(seal.Id)).IsValid.Should().BeTrue("the signature covers it");

        // After a restart, an entry written past the seal with the plain hash is a break.
        db.Notes.Add(new IncidentManager.Domain.Entities.AnalystNote
        {
            CaseId = await db.Cases.Select(c => c.Id).FirstAsync(), Body = "plain", CreatedBy = "x", CreatedAtUtc = _clock.UtcNow,
        });
        await db.SaveChangesAsync();
        var result = await keyed.VerifyAsync();
        result.IsValid.Should().BeFalse();
        result.Detail.Should().Contain($"keyed from entry #{head + 1}");
    }

    [Fact]
    public async Task A_keyed_seal_over_the_same_head_as_an_older_plain_one_is_the_one_read(/* BUG-401 */)
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var head = await db.AuditLog.MaxAsync(a => a.Sequence);
        await NewService(db).SealAsync();   // plain: keyed from nowhere
        _clock.UtcNow = _clock.UtcNow.AddMinutes(5);
        var keyed = new IntegrityService(NewFactory(), _hasher, _signer, _store, _user, _clock, _monitor, _alerts,
            chainKeys: new OneKey());
        (await keyed.SealAsync())!.KeyedFromSequence.Should().Be(head + 1);   // same head, nothing written since

        db.Notes.Add(new IncidentManager.Domain.Entities.AnalystNote
        {
            CaseId = await db.Cases.Select(c => c.Id).FirstAsync(), Body = "plain", CreatedBy = "x", CreatedAtUtc = _clock.UtcNow,
        });
        await db.SaveChangesAsync();

        (await keyed.VerifyAsync()).IsValid.Should().BeFalse("the newest seal says keying starts here, so a plain entry is a break");
    }

    private sealed class OneKey : IChainKeyring
    {
        private static readonly byte[] Secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        public string? CurrentKeyId => ChainKeyring.KeyIdOf(Secret);
        public byte[]? Key(string keyId) => keyId == CurrentKeyId ? Secret : null;
        public IReadOnlyList<string> KeyIds => [CurrentKeyId!];
        public string? Source => "test";
    }

    // F-26: each seal goes to the SIEM, which keeps the copy apart from CaseBook's database and servers.
    [Fact]
    public async Task A_seal_is_sent_to_the_siem_and_its_folder_copy_recorded()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var siem = new CapturingSecurityEventSink();
        var copies = new SealCopyStatus();
        var svc = new IntegrityService(NewFactory(), _hasher, _signer, _store, _user, _clock, _monitor, _alerts,
            siem: siem, copies: copies);

        var seal = (await svc.SealAsync())!;

        var e = siem.Events.Should().ContainSingle(x => x.EventId == 5004).Subject;
        e.TargetId.Should().Be(seal.UpToSequence.ToString(System.Globalization.CultureInfo.InvariantCulture));
        e.Detail.Should().Be($"head={seal.ChainHeadHash} key={seal.KeyId} sealedAtUtc=2026-08-08T00:00:00.0000000Z");
        copies.Snapshot().Should().ContainSingle(c => c.Destination == IntegrityService.FolderCopy && c.Ok);
    }

    [Fact]
    public async Task A_failed_folder_copy_keeps_the_seal_and_is_reported()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var siem = new CapturingSecurityEventSink();
        var copies = new SealCopyStatus();
        var svc = new IntegrityService(NewFactory(), _hasher, _signer, new FailingStore(), _user, _clock, _monitor, _alerts,
            siem: siem, copies: copies);

        var seal = await svc.SealAsync();

        seal.Should().NotBeNull("the seal stands even when its copy fails");
        siem.Events.Select(x => x.EventId).Should().Equal(5004, 5005);
        copies.Snapshot().Single().Should().Match<SealCopyResult>(c => !c.Ok && c.LastError == "share unreachable" && c.LastSuccessUtc == null);
    }

    // F-25: with the chain key on, every entry the app writes is keyed and the chain still verifies end to end.
    [Fact]
    public async Task With_the_chain_key_on_saved_changes_are_keyed_and_verify()
    {
        var key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var secrets = new OneSecret("@cyberark:Safe=S;Object=Chain", Convert.ToBase64String(key));
        var ring = new ChainKeyring(Options.Create(new SealSigningOptions
        {
            SigningKeyPath = Path.Combine(_workDir, "k.pem"),
            ChainKey = new ChainKeyOptions { Enabled = true, Secret = "@cyberark:Safe=S;Object=Chain" }
        }), secrets);
        var keyed = new HashChainService(ring);
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(keyed, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options;
        await using (var db = new AppDbContext(options))
        {
            db.Database.EnsureCreated();
            await DevDataSeeder.SeedAsync(db, _clock);
        }

        await using (var db = new AppDbContext(options))
            (await db.AuditLog.AnyAsync(a => a.HashKeyId != ring.CurrentKeyId)).Should().BeFalse("every entry was written keyed");
        var svc = new IntegrityService(new TestDbContextFactory(options), keyed, _signer, _store, _user, _clock, _monitor, _alerts);
        (await svc.VerifyAsync()).IsValid.Should().BeTrue();
        (await new IntegrityService(new TestDbContextFactory(options), _hasher, _signer, _store, _user, _clock, _monitor, _alerts)
            .VerifyAsync()).IsValid.Should().BeFalse("without the key the keyed entries can't be checked");
    }

    private sealed class OneSecret(string reference, string value) : ISecretProvider
    {
        public ValueTask<string?> ResolveAsync(string? configuredValue, CancellationToken ct = default) =>
            ValueTask.FromResult(configuredValue == reference ? value : configuredValue);
    }

    // F-27: each extra copy is tried after the folder; one that fails is recorded under its own name.
    [Fact]
    public async Task Extra_seal_copies_are_each_tried_and_recorded()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var siem = new CapturingSecurityEventSink();
        var copies = new SealCopyStatus();
        var ok = new FakeCopier("Email", fail: false);
        var bad = new FakeCopier("Timestamp authority", fail: true);
        var svc = new IntegrityService(NewFactory(), _hasher, _signer, _store, _user, _clock, _monitor, _alerts,
            siem: siem, copies: copies, copiers: [ok, bad]);

        (await svc.SealAsync()).Should().NotBeNull();

        ok.Copied.Should().Be(1);
        copies.Snapshot().Select(c => (c.Destination, c.Ok)).Should().BeEquivalentTo(
            [(IntegrityService.FolderCopy, true), ("Email", true), ("Timestamp authority", false)]);
        siem.Events.Should().ContainSingle(e => e.EventId == 5005).Which.Detail.Should().Be("Timestamp authority: no answer");
    }

    private sealed class FakeCopier(string name, bool fail) : ISealCopier
    {
        public int Copied { get; private set; }
        public string Name => name;
        public Task CopyAsync(IncidentManager.Domain.Entities.IntegritySeal seal, CancellationToken ct = default)
        {
            if (fail) throw new HttpRequestException("no answer");
            Copied++;
            return Task.CompletedTask;
        }
    }

    private sealed class FailingStore : ISealStore
    {
        public Task ExportAsync(IncidentManager.Domain.Entities.IntegritySeal seal, CancellationToken ct = default) =>
            throw new IOException("share unreachable");
    }

    [Fact]
    public async Task Verify_detects_history_rewritten_after_the_seal()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewService(db);
        var seal = await svc.SealAsync();

        // Rewrite the audit entry the seal covers (AuditLog is outside the interceptor's own chain).
        var head = await db.AuditLog.OrderByDescending(a => a.Sequence).FirstAsync();
        head.EntryHash = new string('0', 64);
        await db.SaveChangesAsync();

        var result = await svc.VerifySealAsync(seal!.Id);

        // The signature is still authentic, but the live chain head no longer matches the seal.
        result.SignatureValid.Should().BeTrue();
        result.ChainMatches.Should().BeFalse();
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task The_monitor_hashes_new_entries_each_cycle_and_the_whole_chain_every_few_hours(/* BUG-257 */)
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var state = new IntegrityCheckState();
        var svc = new IntegrityService(NewFactory(), _hasher, _signer, _store, _user, _clock, _monitor, _alerts, state: state);

        (await svc.MonitorAndTrackAsync()).IsValid.Should().BeTrue();   // the first cycle is a full one
        state.LastFullUtc.Should().Be(_clock.UtcNow);

        // A record edited in the database is still found at the next cycle: every record is checked each time.
        var note = await db.Notes.FirstAsync();
        await db.Database.ExecuteSqlRawAsync("UPDATE AnalystNotes SET Body = 'rewritten' WHERE Id = {0}", note.Id);
        (await svc.MonitorAndTrackAsync()).IsValid.Should().BeFalse("a record changed outside CaseBook is found within a cycle");
        await db.Database.ExecuteSqlRawAsync("UPDATE AnalystNotes SET Body = {0} WHERE Id = {1}", note.Body, note.Id);
        (await svc.MonitorAndTrackAsync()).IsValid.Should().BeTrue();

        // An old audit entry rewritten is left to the full check: not the next cycle, but "Verify now", or within FullEvery.
        var old = await db.AuditLog.OrderBy(a => a.Sequence).Skip(1).FirstAsync();
        old.EntryHash = new string('0', 64);
        await db.SaveChangesAsync();
        _clock.UtcNow = _clock.UtcNow.AddMinutes(10);
        (await svc.MonitorAndTrackAsync()).IsValid.Should().BeTrue("a cycle hashes only the entries written since the last");
        (await svc.VerifyAndTrackAsync()).IsValid.Should().BeFalse("Verify now re-hashes the whole chain");
        _clock.UtcNow = _clock.UtcNow.Add(IntegrityCheckState.FullEvery);
        (await svc.MonitorAndTrackAsync()).IsValid.Should().BeFalse("and so does the monitor, every FullEvery");
    }

    [Fact]
    public async Task VerifyAndTrack_fires_the_alarm_once_when_the_chain_is_broken()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewService(db);

        // An intact chain raises no alarm and reports valid.
        var intact = await svc.VerifyAndTrackAsync();
        intact.IsValid.Should().BeTrue(intact.Detail);
        _alerts.Fired.Should().BeEmpty();
        _monitor.Current!.IsValid.Should().BeTrue();

        // Corrupt an audit row so the chain no longer verifies (AuditLog is outside the interceptor's chain).
        var entry = await db.AuditLog.OrderBy(a => a.Sequence).Skip(1).FirstAsync();
        entry.EntryHash = new string('0', 64);
        await db.SaveChangesAsync();

        // First detection fires exactly one alarm and records the broken status for the banner.
        (await svc.VerifyAndTrackAsync()).IsValid.Should().BeFalse();
        _alerts.Fired.Should().ContainSingle();
        _monitor.Current!.IsValid.Should().BeFalse();

        // Re-checking while still broken must not re-alarm (deduplicated per broken episode).
        await svc.VerifyAndTrackAsync();
        _alerts.Fired.Should().ContainSingle();
    }

    [Fact]
    public async Task VerifyAndTrack_catches_a_competent_rewrite_the_chain_check_alone_would_miss()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewService(db);
        await svc.SealAsync();

        // Baseline: intact chain + valid seal → no alarm.
        (await svc.VerifyAndTrackAsync()).IsValid.Should().BeTrue();
        _alerts.Fired.Should().BeEmpty();

        // A *competent* tamper: change a sealed entry's content AND recompute its hash so the chain stays
        // internally consistent — the unkeyed VerifyChain would be fooled. This is exactly what the signed
        // seal defends against, and (S-05) it must now trip the automatic monitor, not just a manual check.
        var head = await db.AuditLog.OrderByDescending(a => a.Sequence).FirstAsync();
        var prev = await db.AuditLog.Where(a => a.Sequence == head.Sequence - 1).FirstOrDefaultAsync();
        head.Summary = (head.Summary ?? "") + " [rewritten]";
        _hasher.ChainAppend(head, prev); // recompute EntryHash for the new content → chain stays valid
        await db.SaveChangesAsync();

        // The chain check alone is fooled...
        (await svc.VerifyAsync()).IsValid.Should().BeTrue();

        // ...but VerifyAndTrack now catches it via the seal and fires the alarm exactly once.
        var result = await svc.VerifyAndTrackAsync();
        result.IsValid.Should().BeFalse();
        result.FirstBrokenSequence.Should().Be(head.Sequence);
        _alerts.Fired.Should().ContainSingle();
        _monitor.Current!.IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task SealIfDue_seals_when_none_or_overdue_and_skips_when_recent()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewService(db);

        // No seal yet → seals.
        (await svc.SealIfDueAsync(TimeSpan.FromHours(6))).Should().NotBeNull();
        // A seal now exists and no time has passed → not due.
        (await svc.SealIfDueAsync(TimeSpan.FromHours(6))).Should().BeNull();
        // Advance past the interval → due again.
        _clock.UtcNow = _clock.UtcNow.AddHours(7);
        (await svc.SealIfDueAsync(TimeSpan.FromHours(6))).Should().NotBeNull();
    }

    public void Dispose()
    {
        _signer.Dispose();
        _connection.Dispose();
        try { if (Directory.Exists(_workDir)) Directory.Delete(_workDir, recursive: true); } catch { /* best effort */ }
    }
}
