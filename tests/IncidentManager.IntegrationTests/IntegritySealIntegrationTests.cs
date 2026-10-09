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
    public async Task VerifyAndTrack_fires_the_alarm_once_when_the_chain_is_broken()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        var svc = NewService(db);

        // An intact chain raises no alarm and reports valid.
        (await svc.VerifyAndTrackAsync()).IsValid.Should().BeTrue();
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
