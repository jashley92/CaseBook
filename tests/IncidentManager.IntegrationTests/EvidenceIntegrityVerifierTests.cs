using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Evidence;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Enums;
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
/// F-17: the evidence-at-rest verifier re-hashes stored bytes against each row's recorded SHA-256 (which
/// the audit chain protects) and reports drift — hash mismatch, missing, or unreadable — without touching
/// the database, alarming once per drift episode. Uses the real FileEvidenceStore over a temp directory so
/// the corruption cases exercise real filesystem behaviour (and stay cross-platform for CI on Linux).
/// </summary>
public sealed class EvidenceIntegrityVerifierTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 9, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();
    private readonly string _storeDir;

    public EvidenceIntegrityVerifierTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _storeDir = Path.Combine(Path.GetTempPath(), "im-evidence-verify-tests", Guid.NewGuid().ToString("N"));
        _user.RoleSet = [AppRole.IncidentCommander];
    }

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options);

    private FileEvidenceStore Store() =>
        new(Options.Create(new EvidenceStoreOptions { RootPath = _storeDir }));

    private EvidenceService NewEvidenceService() => new(NewFactory(), Store(), _user, _clock);

    private sealed class CapturingNotifier : IEvidenceIntegrityAlertNotifier
    {
        public List<EvidenceVerificationResult> Calls { get; } = new();
        public Task OnDriftDetectedAsync(EvidenceVerificationResult result, CancellationToken ct = default)
        {
            Calls.Add(result);
            return Task.CompletedTask;
        }
    }

    private EvidenceIntegrityVerifier NewVerifier(IEvidenceIntegrityMonitor monitor, IEvidenceIntegrityAlertNotifier notifier) =>
        new(NewFactory(), Store(), _clock, monitor, notifier);

    private string AbsPathFor(string storagePath) =>
        Path.Combine(_storeDir, storagePath.Replace('/', Path.DirectorySeparatorChar));

    private async Task<Guid> SeedCaseAsync()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        return (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
    }

    private async Task<(Guid Id, string StoragePath)> UploadAsync(Guid caseId, string name, string body)
    {
        var svc = NewEvidenceService();
        await using var s = new MemoryStream(Encoding.UTF8.GetBytes(body));
        var ev = await svc.UploadAsync(caseId, name, "application/octet-stream", s, null);
        return (ev.Id, ev.StoragePath);
    }

    [Fact]
    public async Task A_clean_store_reports_no_drift()
    {
        var caseId = await SeedCaseAsync();
        await UploadAsync(caseId, "a.bin", "alpha");
        await UploadAsync(caseId, "b.bin", "bravo");

        var result = await NewVerifier(new EvidenceIntegrityMonitor(), new CapturingNotifier()).VerifyAllAsync();

        result.CheckedCount.Should().Be(2);
        result.IsClean.Should().BeTrue();
        result.Drifts.Should().BeEmpty();
    }

    [Fact]
    public async Task A_corrupted_file_is_reported_as_hash_mismatch()
    {
        var caseId = await SeedCaseAsync();
        var (id, storagePath) = await UploadAsync(caseId, "evidence.bin", "original-bytes");
        await UploadAsync(caseId, "intact.bin", "unchanged");

        // Silently rewrite the stored bytes under the store — the recorded SHA-256 (chain-protected) no
        // longer describes what's on disk.
        await File.WriteAllTextAsync(AbsPathFor(storagePath), "tampered-bytes");

        var result = await NewVerifier(new EvidenceIntegrityMonitor(), new CapturingNotifier()).VerifyAllAsync();

        result.CheckedCount.Should().Be(2);
        var drift = result.Drifts.Should().ContainSingle().Subject;
        drift.EvidenceId.Should().Be(id);
        drift.CaseNumber.Should().Be("2026-01_Phishing_Wave");
        drift.Kind.Should().Be(EvidenceDriftKind.HashMismatch);
        drift.ActualSha256.Should().NotBeNullOrEmpty().And.NotBe(drift.ExpectedSha256);
    }

    [Fact]
    public async Task A_missing_file_is_reported_as_missing()
    {
        var caseId = await SeedCaseAsync();
        var (id, storagePath) = await UploadAsync(caseId, "gone.bin", "will-be-deleted");

        File.Delete(AbsPathFor(storagePath));

        var result = await NewVerifier(new EvidenceIntegrityMonitor(), new CapturingNotifier()).VerifyAllAsync();

        var drift = result.Drifts.Should().ContainSingle().Subject;
        drift.EvidenceId.Should().Be(id);
        drift.Kind.Should().Be(EvidenceDriftKind.Missing);
        drift.ActualSha256.Should().BeNull();
    }

    [Fact]
    public async Task An_unreadable_file_is_reported_as_unreadable()
    {
        var caseId = await SeedCaseAsync();
        var (id, storagePath) = await UploadAsync(caseId, "blocked.bin", "content");

        // Replace the file with a directory of the same name: opening it as a file for read throws
        // UnauthorizedAccessException on both Windows and Linux — a portable "can't read the bytes".
        var abs = AbsPathFor(storagePath);
        File.Delete(abs);
        Directory.CreateDirectory(abs);

        var result = await NewVerifier(new EvidenceIntegrityMonitor(), new CapturingNotifier()).VerifyAllAsync();

        var drift = result.Drifts.Should().ContainSingle().Subject;
        drift.EvidenceId.Should().Be(id);
        drift.Kind.Should().Be(EvidenceDriftKind.Unreadable);
    }

    [Fact]
    public async Task Track_fires_the_alarm_once_per_drift_episode_and_re_alarms_after_recovery()
    {
        var caseId = await SeedCaseAsync();
        var (_, storagePath) = await UploadAsync(caseId, "evidence.bin", "original-bytes");
        var monitor = new EvidenceIntegrityMonitor();
        var notifier = new CapturingNotifier();
        var abs = AbsPathFor(storagePath);

        // Clean pass: no alarm.
        await NewVerifier(monitor, notifier).VerifyAndTrackAsync();
        notifier.Calls.Should().BeEmpty();

        // Corrupt, then two passes: the alarm fires exactly once for the episode.
        await File.WriteAllTextAsync(abs, "tampered-bytes");
        await NewVerifier(monitor, notifier).VerifyAndTrackAsync();
        await NewVerifier(monitor, notifier).VerifyAndTrackAsync();
        notifier.Calls.Should().HaveCount(1, "a persisting drift alarms once, not every pass");

        // Recover the original bytes: clean pass, still one total call, latch reset.
        await File.WriteAllTextAsync(abs, "original-bytes");
        await NewVerifier(monitor, notifier).VerifyAndTrackAsync();
        monitor.Current!.IsClean.Should().BeTrue();
        notifier.Calls.Should().HaveCount(1);

        // A fresh drift after recovery alarms again.
        await File.WriteAllTextAsync(abs, "tampered-again");
        await NewVerifier(monitor, notifier).VerifyAndTrackAsync();
        notifier.Calls.Should().HaveCount(2);
    }

    public void Dispose()
    {
        _connection.Dispose();
        if (Directory.Exists(_storeDir)) Directory.Delete(_storeDir, recursive: true);
    }
}
