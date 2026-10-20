using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using IncidentManager.KeyTool;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// casebook-keytool verify-restore, the check a restore drill records as "verified": on a copy laid out as a site folder
/// describes it, an intact one passes every check; an altered audit entry, a seal whose key isn't held, an evidence file
/// missing or changed, each fails the check that should catch it. The seal keys can come from the site or be given.
/// </summary>
public sealed class RestoreCheckTests : IDisposable
{
    private readonly string _site = Path.Combine(Path.GetTempPath(), "im-restore", Guid.NewGuid().ToString("N"));
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };

    private string Data => Path.Combine(_site, "data");
    private string Evidence => Path.Combine(Data, "evidence-store");
    private string KeyPath => Path.Combine(Data, "keys", "seal-signing.pem");
    private string ConnectionString => $"Data Source={Path.Combine(Data, "casebook.db")};Pooling=False";

    public RestoreCheckTests()
    {
        Directory.CreateDirectory(Evidence);
        File.WriteAllText(Path.Combine(_site, "appsettings.Production.json"), System.Text.Json.JsonSerializer.Serialize(new
        {
            ConnectionStrings = new { Default = ConnectionString },
            Database = new { Provider = "Sqlite" },
            EvidenceStore = new { RootPath = Evidence },
            Integrity = new { SigningKeyPath = KeyPath },
        }));
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_site, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(ConnectionString)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
        .Options;

    // A real CaseBook: the demo cases (an audit chain), two evidence files on the store, and a seal over it all.
    private async Task<List<string>> BuildAsync()
    {
        await using (var db = new AppDbContext(Options()))
        {
            await db.Database.EnsureCreatedAsync();
            await DevDataSeeder.SeedAsync(db, _clock);
        }
        var files = new List<string>();
        await using (var db = new AppDbContext(Options()))
        {
            var caseId = await db.Cases.Select(c => c.Id).FirstAsync();
            foreach (var name in new[] { "a.log", "b.csv" })
            {
                var bytes = Encoding.UTF8.GetBytes($"evidence {name} {Guid.NewGuid()}");
                var relative = Path.Combine(caseId.ToString("N"), Guid.NewGuid().ToString("N") + ".bin");
                Directory.CreateDirectory(Path.GetDirectoryName(Path.Combine(Evidence, relative))!);
                await File.WriteAllBytesAsync(Path.Combine(Evidence, relative), bytes);
                db.Evidence.Add(new Evidence
                {
                    CaseId = caseId, OriginalFileName = name, SizeBytes = bytes.Length, StoragePath = relative,
                    Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), CreatedBy = "analyst1", CreatedAtUtc = _clock.UtcNow,
                });
                files.Add(Path.Combine(Evidence, relative));
            }
            await db.SaveChangesAsync();
        }
        using var signer = new RsaSealSigner(Microsoft.Extensions.Options.Options.Create(new SealSigningOptions { SigningKeyPath = KeyPath, AllowKeyGeneration = true }));
        var factory = new TestDbContextFactory(Options());
        await new IntegrityService(factory, _hasher, signer, new FileSealStore(Microsoft.Extensions.Options.Options.Create(new SealSigningOptions { ExportPath = Path.Combine(Data, "seals") })),
            _user, _clock, new IntegrityMonitor(), new NoAlerts()).SealAsync();
        SqliteConnection.ClearAllPools();
        return files;
    }

    private RestoreReport Check(int sample = 200, bool hashAll = false, string? publicKeys = null) =>
        RestoreCheck.Run(Site.Load(_site), sample, hashAll, publicKeys, null, TextWriter.Null);

    private sealed class NoAlerts : IIntegrityAlertNotifier
    {
        public Task OnChainBrokenAsync(ChainVerificationResult result, CancellationToken ct = default) => Task.CompletedTask;
    }

    [Fact]
    public async Task An_intact_copy_passes_every_check()
    {
        await BuildAsync();
        var report = Check();
        report.Checks.Select(c => c.Check).Should().Equal("Database", "Evidence key", "Audit chain", "Seals", "Evidence files", "Evidence hashes (sample)");
        report.Checks.Where(c => !c.Passed).Select(c => $"{c.Check}: {c.Detail}").Should().BeEmpty();
        report.Passed.Should().BeTrue();
        RestoreCheck.ToJson(report).Should().Contain("\"passed\": true");
    }

    [Fact]
    public async Task An_altered_audit_entry_breaks_the_chain()
    {
        await BuildAsync();
        await using (var raw = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(ConnectionString).Options))
            await raw.Database.ExecuteSqlRawAsync("UPDATE AuditLog SET Actor = 'mallory' WHERE Sequence = 3");
        SqliteConnection.ClearAllPools();

        var report = Check();
        report.Passed.Should().BeFalse();
        report.Checks.Single(c => c.Check == "Audit chain").Should().Match<RestoreCheckResult>(c => !c.Passed && c.Detail.Contains("sequence 3"));
    }

    [Fact]
    public async Task A_seal_whose_key_is_not_held_fails_until_its_public_key_is_given()
    {
        await BuildAsync();
        var keyId = SigningKeyCommands.PublicKey(KeyPath, null, "CurrentUser", null);
        var given = Path.Combine(_site, "public-keys");
        Directory.CreateDirectory(given);
        File.WriteAllText(Path.Combine(given, $"{keyId.KeyId}.pem"), keyId.Pem);
        File.Delete(KeyPath);   // a recovery server without the signing key

        var without = Check();
        without.Checks.Single(c => c.Check == "Seals").Should().Match<RestoreCheckResult>(c => !c.Passed && c.Detail.Contains("isn't available here"));
        Check(publicKeys: given).Checks.Single(c => c.Check == "Seals").Passed.Should().BeTrue("the public key is all a seal needs to be checked");
    }

    [Fact]
    public async Task A_missing_or_changed_evidence_file_is_found()
    {
        var files = await BuildAsync();
        File.Delete(files[0]);
        var bytes = await File.ReadAllBytesAsync(files[1]);
        bytes[0] ^= 0xFF;   // same size, different bytes
        await File.WriteAllBytesAsync(files[1], bytes);

        var report = Check(hashAll: true);
        report.Checks.Single(c => c.Check == "Evidence files").Should().Match<RestoreCheckResult>(c => !c.Passed && c.Detail.Contains("a.log: missing"));
        report.Checks.Single(c => c.Check == "Evidence hashes (all)").Should().Match<RestoreCheckResult>(c => !c.Passed && c.Detail.Contains("b.csv: SHA-256 differs"));
        report.Passed.Should().BeFalse();
    }

    [Fact]
    public void A_database_that_is_not_there_fails_without_going_further()
    {
        var report = Check();
        report.Passed.Should().BeFalse();
        report.Checks.Should().ContainSingle().Which.Check.Should().Be("Database");
    }
}
