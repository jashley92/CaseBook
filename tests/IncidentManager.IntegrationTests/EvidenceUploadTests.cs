using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Evidence;
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
/// Locks the server-side behaviour the U-39 drag-drop bulk upload relies on: each file uploaded to a case
/// (the component's OnDropped loops UploadAsync per dropped file) becomes its own hashed, custody-tracked
/// evidence row, independent of the others, and the audit chain stays valid.
/// </summary>
public sealed class EvidenceUploadTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();
    private readonly string _storeDir;

    public EvidenceUploadTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _storeDir = Path.Combine(Path.GetTempPath(), "im-evidence-tests", Guid.NewGuid().ToString("N"));
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

    private EvidenceService NewEvidenceService() =>
        new(NewFactory(), new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = _storeDir })),
            _user, _clock);

    private static string Sha256Hex(string content) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content))).ToLowerInvariant();

    [Fact]
    public async Task Dropping_multiple_files_yields_independent_hashed_custody_tracked_evidence()
    {
        Guid caseId;
        await using (var db = NewContext())
        {
            await DevDataSeeder.SeedAsync(db, _clock);
            caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
        }

        var svc = NewEvidenceService();

        // Mirror OnDropped: one UploadAsync per dropped file.
        var files = new[] { ("dropped-a.txt", "alpha"), ("dropped-b.txt", "bravo"), ("shot.png", "screenshot-bytes") };
        foreach (var (name, body) in files)
        {
            await using var stream = new MemoryStream(Encoding.UTF8.GetBytes(body));
            await svc.UploadAsync(caseId, name, "text/plain", stream, null);
        }

        await using (var db = NewContext())
        {
            var evidence = await db.Evidence.Where(e => e.CaseId == caseId).ToListAsync();
            evidence.Should().HaveCount(3);

            foreach (var (name, body) in files)
            {
                var row = evidence.Single(e => e.OriginalFileName == name);
                row.Sha256.Should().Be(Sha256Hex(body), "each dropped file is hashed independently");
                row.SizeBytes.Should().Be(Encoding.UTF8.GetByteCount(body));
            }

            // Distinct content → distinct hashes and distinct storage paths (no collision across the batch).
            evidence.Select(e => e.Sha256).Distinct().Should().HaveCount(3);
            evidence.Select(e => e.StoragePath).Distinct().Should().HaveCount(3);

            // Every upload recorded a chain-of-custody entry.
            var custody = await db.CustodyEvents.CountAsync();
            custody.Should().BeGreaterThanOrEqualTo(3);

            // The tamper-evident chain is intact after the batch.
            var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
            _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        }
    }

    [Fact]
    public async Task A_pasted_screenshot_streams_back_with_a_matching_hash()
    {
        Guid caseId;
        await using (var db = NewContext())
        {
            await DevDataSeeder.SeedAsync(db, _clock);
            caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
        }

        var svc = NewEvidenceService();
        const string body = "pretend-png-bytes";
        Guid evId;
        await using (var s = new MemoryStream(Encoding.UTF8.GetBytes(body)))
            evId = (await svc.UploadAsync(caseId, "pasted-screenshot-20260824-120000.png", "image/png", s, "clip")).Id;

        var (evidence, content) = await svc.OpenAsync(evId);
        await using (content)
        {
            using var ms = new MemoryStream();
            await content.CopyToAsync(ms);
            Convert.ToHexString(SHA256.HashData(ms.ToArray())).ToLowerInvariant().Should().Be(evidence.Sha256);
        }
        evidence.OriginalFileName.Should().StartWith("pasted-screenshot-");
        evidence.Description.Should().Be("clip");
    }

    [Fact]
    public async Task Only_an_explicit_download_records_a_custody_event()
    {
        Guid caseId;
        await using (var db = NewContext())
        {
            await DevDataSeeder.SeedAsync(db, _clock);
            caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
        }

        var svc = NewEvidenceService();
        Guid evId;
        await using (var s = new MemoryStream(Encoding.UTF8.GetBytes("bytes")))
            evId = (await svc.UploadAsync(caseId, "shot.png", "image/png", s, null)).Id;

        // S-03: a passive inline render (recordDownload:false) must NOT append a "Downloaded" custody
        // event — only the "Uploaded" event from the upload should exist.
        (await svc.OpenAsync(evId, recordDownload: false)).Content.Dispose();
        (await svc.GetCustodyAsync(evId)).Select(e => e.Action)
            .Should().ContainSingle().Which.Should().Be("Uploaded");

        // An explicit download (recordDownload:true) records the custody event.
        (await svc.OpenAsync(evId, recordDownload: true)).Content.Dispose();
        (await svc.GetCustodyAsync(evId)).Select(e => e.Action)
            .Should().BeEquivalentTo("Uploaded", "Downloaded");
    }

    public void Dispose()
    {
        _connection.Dispose();
        if (Directory.Exists(_storeDir)) Directory.Delete(_storeDir, recursive: true);
    }
}
