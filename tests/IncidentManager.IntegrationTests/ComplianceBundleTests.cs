using System.IO.Compression;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Exercises the compliance evidence bundle (C-01) end to end: seed activity, seal the chain, build a
/// dated bundle, and confirm it packages a verified audit-chain segment + seals and records its own export.
/// </summary>
public sealed class ComplianceBundleTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };
    private readonly string _workDir = Path.Combine(Path.GetTempPath(), "im-bundle-tests", Guid.NewGuid().ToString("N"));
    private readonly RsaSealSigner _signer;
    private readonly FileSealStore _store;

    public ComplianceBundleTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _signer = new RsaSealSigner(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(_workDir, "k.pem") }));
        _store = new FileSealStore(Options.Create(new SealSigningOptions { ExportPath = Path.Combine(_workDir, "seals") }));
    }

    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private ComplianceBundleService NewBundleService(AppDbContext db) =>
        new(NewFactory(), _hasher, _signer, new StubUserDirectory(), new AuditWriter(db, _hasher, _user, _clock), _user, _clock);

    private static Dictionary<string, string> Unzip(byte[] bytes)
    {
        using var archive = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
        return archive.Entries.ToDictionary(e => e.Name, e =>
        {
            using var reader = new StreamReader(e.Open(), Encoding.UTF8);
            return reader.ReadToEnd();
        });
    }

    [Fact]
    public async Task Bundle_packages_a_verified_segment_and_seals_and_records_its_export()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        await new IntegrityService(NewFactory(), _hasher, _signer, _store, _user, _clock,
            new IntegrityMonitor(), new NoOpIntegrityAlerts()).SealAsync();

        var auditBefore = await db.AuditLog.CountAsync();

        var from = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var to = new DateTimeOffset(2026, 12, 31, 23, 59, 59, TimeSpan.Zero);
        var bundle = await NewBundleService(db).BuildAsync(from, to);

        // The package contains every expected file.
        var files = Unzip(bundle.Content);
        files.Keys.Should().BeEquivalentTo(
            "manifest.txt", "audit-chain.csv", "seals.csv", "signing-public-key.pem", "VERIFY.txt");

        // Verified content: intact chain, real segment, an authentic covering seal.
        files["manifest.txt"].Should().Contain("Whole-chain verification : VALID");
        bundle.Model.Segment.Should().NotBeEmpty();
        bundle.Model.Seals.Should().NotBeEmpty();
        bundle.Model.CoveringSeal!.IsValid.Should().BeTrue();
        files["signing-public-key.pem"].Should().Contain("BEGIN PUBLIC KEY");

        // Generating the bundle is itself a recorded, hash-chained Export — and the chain still verifies.
        (await db.AuditLog.CountAsync()).Should().Be(auditBefore + 1);
        (await db.AuditLog.OrderByDescending(a => a.Sequence).FirstAsync()).Action.Should().Be(AuditAction.Export);
        _hasher.VerifyChain(await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task Empty_range_yields_a_bundle_with_no_segment_entries()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);

        // A window before any activity: no entries fall inside it.
        var from = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var to = new DateTimeOffset(2020, 12, 31, 23, 59, 59, TimeSpan.Zero);
        var bundle = await NewBundleService(db).BuildAsync(from, to);

        bundle.Model.Segment.Should().BeEmpty();
        Unzip(bundle.Content)["manifest.txt"].Should().Contain("Sequence span      : (no entries in this range)");
    }

    /// <summary>Identity directory stub: resolves ids to themselves — enough for the manifest header.</summary>
    private sealed class StubUserDirectory : IUserDirectory
    {
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<UserSummary> All() => Array.Empty<UserSummary>();
        public UserSummary? Resolve(string userId) => null;
        public string DisplayFor(string? userId) => userId ?? "—";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
    }

    /// <summary>No-op alert notifier: the bundle tests seal an intact chain, so no alarm should fire.</summary>
    private sealed class NoOpIntegrityAlerts : IIntegrityAlertNotifier
    {
        public Task OnChainBrokenAsync(ChainVerificationResult result, CancellationToken ct = default) => Task.CompletedTask;
    }

    public void Dispose()
    {
        _signer.Dispose();
        _connection.Dispose();
        try { if (Directory.Exists(_workDir)) Directory.Delete(_workDir, recursive: true); } catch { /* best effort */ }
    }
}
