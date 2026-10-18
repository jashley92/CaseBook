using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using IncidentManager.KeyTool;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// PROD-57: casebook-keytool on a site laid out as the installer lays it out. Shares split here turn encryption on at the
/// app's next check and rebuild the key; a holder checks a share alone; a drill with shares or a recovery PFX opens the key
/// and is recorded; recovery moves the key onto a new server certificate the app then opens; export writes the original
/// files with a manifest. The tool never makes a key, and a wrong certificate or share set is refused.
/// </summary>
[Collection("CertificateStore")]
public sealed class KeyToolTests : IDisposable
{
    private readonly string _site = Path.Combine(Path.GetTempPath(), "im-keytool", Guid.NewGuid().ToString("N"));
    private readonly List<X509Certificate2> _installed = [];

    public KeyToolTests()
    {
        Directory.CreateDirectory(_site);
        Directory.CreateDirectory(Evidence);   // as CaseBook's start-up makes a fresh store's folder
    }

    public void Dispose()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        foreach (var c in _installed)
        {
            store.Remove(c);
            try { if (OperatingSystem.IsWindows() && c.GetRSAPrivateKey() is RSACng cng) cng.Key.Delete(); }
            catch (CryptographicException) { /* gone */ }
            c.Dispose();
        }
        SqliteCleanup();
        try { Directory.Delete(_site, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private static void SqliteCleanup() => Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

    private X509Certificate2 Installed(string name)
    {
        using var rsa = RSA.Create(3072);
        using var made = new CertificateRequest($"CN={name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var cert = X509CertificateLoader.LoadPkcs12(made.Export(X509ContentType.Pfx, "t"), "t",
            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);
        _installed.Add(cert);
        return cert;
    }

    private string Evidence => Path.Combine(_site, "data", "evidence-store");
    private string Database => Path.Combine(_site, "data", "casebook.db");

    private void WriteSettings(X509Certificate2 server, params string[] recovery) =>
        File.WriteAllText(Path.Combine(_site, "appsettings.Production.json"), System.Text.Json.JsonSerializer.Serialize(new
        {
            ConnectionStrings = new { Default = $"Data Source={Database}" },
            Database = new { Provider = "Sqlite" },
            EvidenceStore = new { RootPath = Evidence },
            ReportOutput = new { RootPath = Path.Combine(_site, "data", "report-output") },
            Integrity = new { SigningKeyPath = Path.Combine(_site, "data", "keys", "seal-signing.pem") },
            Storage = new { Encryption = new { Enabled = true, CertificateThumbprint = server.Thumbprint, StoreLocation = "CurrentUser", RecoveryCertificates = recovery } },
        }));

    private EvidenceKeyring Ring(Site site, X509Certificate2 server, params string[] recovery) =>
        new(Options.Create(new EvidenceEncryptionOptions { Enabled = true, CertificateThumbprint = server.Thumbprint, StoreLocation = "CurrentUser", RecoveryCertificates = recovery }),
            Options.Create(site.Integrity), Options.Create(new EvidenceStoreOptions { RootPath = site.EvidenceRoot }),
            Options.Create(new ReportOutputOptions { RootPath = site.ReportRoot }), NoChainKeys.Instance);

    [Fact]
    public void Relative_paths_and_a_relative_SQLite_file_are_the_site_folders_wherever_the_tool_is_run()
    {
        // Found on the dev server: the SQLite file resolved against the current folder, so export run from elsewhere
        // opened (and created) an empty database beside the tool.
        File.WriteAllText(Path.Combine(_site, "appsettings.json"), """
            { "ConnectionStrings": { "Default": "Data Source=App_Data/incidentmanager.db" }, "Database": { "Provider": "Sqlite" } }
            """);
        var site = Site.Load(_site);
        var built = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(site.ConnectionString);
        built.DataSource.Should().Be(Path.Combine(_site, "App_Data", "incidentmanager.db"));
        built.Mode.Should().Be(Microsoft.Data.Sqlite.SqliteOpenMode.ReadWrite, "never creates an empty database");
        site.EvidenceRoot.Should().Be(Path.Combine(_site, "App_Data", "evidence-store"));
    }

    [Fact]
    public async Task Shares_split_on_the_server_turn_encryption_on_and_rebuild_the_key_and_a_drill_is_recorded()
    {
        var server = Installed("CaseBook keytool server");
        WriteSettings(server);
        var site = Site.Load(_site);
        var ring = Ring(site, server);
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.NeedsBackup);

        var output = new StringWriter();
        var shares = KeyToolCommands.Split(site, 3, 5, Path.Combine(_site, "shares-out"), output);
        shares.Should().HaveCount(5);
        output.ToString().Should().Contain("any 3 of which rebuild it");
        Directory.GetFiles(Path.Combine(_site, "shares-out")).Should().HaveCount(5);
        if (OperatingSystem.IsWindows())
        {
            // Review finding 11: the share files are readable by administrators (and SYSTEM, and whoever ran it) only.
            var acl = new DirectoryInfo(Path.Combine(_site, "shares-out")).GetAccessControl();
            acl.AreAccessRulesProtected.Should().BeTrue("nothing inherited from the parent folder");
            var holders = new List<string>();
            foreach (System.Security.AccessControl.FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
                holders.Add(rule.IdentityReference.Value);
            holders.Should().NotContain(new[]
            {
                new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null).Value,
                new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.WorldSid, null).Value,
                new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.AuthenticatedUserSid, null).Value,
            });
        }
        KeyEnvelope.Parse(File.ReadAllText(site.EnvelopePath))!.Shares.Should().Match<SharesIssued>(s => s.Threshold == 3 && s.Count == 5);
        File.ReadAllText(site.EnvelopePath).Should().NotContain(shares[0], "the envelope records that shares were issued, never a share");

        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready, "issued shares are a backup: encryption turns on");

        var check = new StringWriter();
        KeyToolCommands.CheckShares([shares[3]], check);
        check.ToString().Should().Contain("share 4").And.Contain(ring.CurrentKeyId!);

        var drill = new StringWriter();
        KeyToolCommands.Verify(site, new Opening(Shares: [shares[0], shares[2], shares[4]]), drill);
        drill.ToString().Should().StartWith("OK: evidence key ").And.Contain("opens with 3 shares");
        KeyEnvelope.Parse(File.ReadAllText(site.EnvelopePath))!.LastDrillUtc.Should().NotBeNull();
        var tooFew = () => KeyToolCommands.Verify(site, new Opening(Shares: [shares[0], shares[1]]), new StringWriter());
        tooFew.Should().Throw<ArgumentException>();
    }

    [Fact]
    public async Task A_recovery_PFX_opens_the_key_and_recover_moves_it_onto_a_new_server_certificate()
    {
        var server = Installed("CaseBook keytool server (old)");
        using var rsa = RSA.Create(3072);
        using var recoveryMade = new CertificateRequest("CN=CaseBook recovery (safe)", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
        var pfx = Path.Combine(_site, "recovery.pfx");
        await File.WriteAllBytesAsync(pfx, recoveryMade.Export(X509ContentType.Pfx, "safe-password"));
        var cer = Path.Combine(_site, "recovery.cer");
        await File.WriteAllBytesAsync(cer, recoveryMade.Export(X509ContentType.Cert));
        WriteSettings(server, cer);
        var site = Site.Load(_site);
        var ring = Ring(site, server, cer);
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        var store = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), ring);
        var stored = await store.SaveAsync(Guid.NewGuid(), new MemoryStream("evidence written under the old certificate"u8.ToArray()));

        var drill = new StringWriter();
        KeyToolCommands.Verify(site, new Opening(PfxPath: pfx, PfxPassword: "safe-password"), drill);
        drill.ToString().Should().Contain("recovery certificate").And.Contain("opens with recovery certificate");
        var wrong = () => KeyToolCommands.Verify(site, new Opening(PfxPath: pfx, PfxPassword: "nope"), new StringWriter());
        wrong.Should().Throw<CryptographicException>();

        // Review finding 8: a target without its private key here couldn't open the key again: refused, nothing changed.
        var publicOnly = X509CertificateLoader.LoadCertificate(Installed("CaseBook keytool public only").Export(X509ContentType.Cert));
        using (var s = new X509Store(StoreName.My, StoreLocation.CurrentUser))
        {
            s.Open(OpenFlags.ReadWrite);
            s.Remove(publicOnly);
            s.Add(publicOnly);   // the certificate alone, its key not on this machine
        }
        var envelopeBefore = File.ReadAllText(site.EnvelopePath);
        var keyless = () => KeyToolCommands.Recover(site, new Opening(PfxPath: pfx, PfxPassword: "safe-password"), publicOnly.Thumbprint,
            "CurrentUser", false, new StringWriter());
        keyless.Should().Throw<Exception>().Where(e => e is InvalidOperationException || e is CryptographicException);
        File.ReadAllText(site.EnvelopePath).Should().Be(envelopeBefore);

        // The old server is gone: a new certificate on a new server, the key recovered onto it from the recovery PFX.
        var renewed = Installed("CaseBook keytool server (new)");
        using (var s = new X509Store(StoreName.My, StoreLocation.CurrentUser)) { s.Open(OpenFlags.ReadWrite); s.Remove(server); }
        KeyToolCommands.Recover(site, new Opening(PfxPath: pfx, PfxPassword: "safe-password"), renewed.Thumbprint, "CurrentUser", false, new StringWriter());
        var after = Ring(site, renewed, cer);
        (await after.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        after.CurrentKeyId.Should().Be(ring.CurrentKeyId, "the same key, so every file still opens");
        var reopened = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), after);
        await using var read = await reopened.OpenReadAsync(stored.StoragePath);
        new StreamReader(read).ReadToEnd().Should().Be("evidence written under the old certificate");
    }

    [Fact]
    public async Task Export_writes_the_original_files_with_a_manifest_and_never_makes_a_key()
    {
        var server = Installed("CaseBook keytool server");
        using var rsa = RSA.Create(3072);
        using var recoveryMade = new CertificateRequest("CN=r", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
        var cer = Path.Combine(_site, "r.cer");
        await File.WriteAllBytesAsync(cer, recoveryMade.Export(X509ContentType.Cert));
        WriteSettings(server, cer);
        var site = Site.Load(_site);

        Directory.CreateDirectory(Path.GetDirectoryName(Database)!);
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite($"Data Source={Database}").Options;
        var clock = new FixedClock(new DateTimeOffset(2026, 10, 17, 9, 0, 0, TimeSpan.Zero));
        await using (var db = new AppDbContext(options))
        {
            await db.Database.EnsureCreatedAsync();
            await DevDataSeeder.SeedAsync(db, clock);
        }
        Guid caseId;
        string caseNumber;
        await using (var db = new AppDbContext(options))
        {
            var c = await db.Cases.FirstAsync();
            (caseId, caseNumber) = (c.Id, c.CaseNumber);
        }

        var plainStore = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }));
        var plain = await plainStore.SaveAsync(caseId, new MemoryStream("stored before encryption"u8.ToArray()));
        var ring = Ring(site, server, cer);
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        var store = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), ring);
        var bytes = RandomNumberGenerator.GetBytes(200_000);
        var encrypted = await store.SaveAsync(caseId, new MemoryStream(bytes));
        await using (var db = new AppDbContext(options))
        {
            // Review finding 11: a row whose stored path leads outside the store (a tampered row) isn't copied out.
            await File.WriteAllTextAsync(Path.Combine(_site, "outside.txt"), "not evidence");
            db.Evidence.Add(new IncidentManager.Domain.Entities.Evidence
            {
                CaseId = caseId, OriginalFileName = "outside.txt", ContentType = "", SizeBytes = 12, Sha256 = new string('0', 64),
                StoragePath = "../../outside.txt", CreatedBy = "seed", CreatedAtUtc = clock.UtcNow,
            });
            foreach (var (s, name) in new[] { (plain, "notes.txt"), (encrypted, "=cmd|' /C calc'!A0.exe") })
                db.Evidence.Add(new IncidentManager.Domain.Entities.Evidence
                {
                    CaseId = caseId, OriginalFileName = name, ContentType = "", SizeBytes = s.SizeBytes, Sha256 = s.Sha256,
                    StoragePath = s.StoragePath, CreatedBy = "seed", CreatedAtUtc = clock.UtcNow,
                });
            await db.SaveChangesAsync();
        }

        var envelopeBefore = File.ReadAllText(site.EnvelopePath);
        var outFolder = Path.Combine(_site, "export");
        var (exported, mismatched) = KeyToolCommands.Export(site, caseNumber, outFolder, null, new StringWriter());
        exported.Should().BeGreaterThanOrEqualTo(3);
        mismatched.Should().Be(1, "the row leading outside the store");
        var files = Directory.GetFiles(Path.Combine(outFolder, caseNumber));
        files.Select(File.ReadAllBytes).Should().Contain(b => b.SequenceEqual(bytes), "the encrypted file comes out as the original");
        files.Select(File.ReadAllText).Should().Contain("stored before encryption");
        var manifest = File.ReadAllText(Path.Combine(outFolder, "manifest.csv"));
        manifest.Should().Contain(encrypted.Sha256).And.Contain("\"'=cmd", "a name starting like a formula is neutralised (C13)");
        manifest.Should().Contain("refused: its stored path leads outside the evidence store");
        Directory.GetFiles(Path.Combine(outFolder, caseNumber)).Select(File.ReadAllText).Should().NotContain("not evidence");
        // PROD-59: export changes nothing but its own record, for CaseBook to put in the audit trail and the SIEM.
        var after = KeyEnvelope.Parse(File.ReadAllText(site.EnvelopePath))!;
        after.Records.Should().ContainSingle(r => r.Kind == KeyToolRecord.Exported)
            .Which.Summary.Should().Contain($"case {caseNumber}").And.Contain("manifest.csv SHA-256");
        after.Records.Single().CaseNumber.Should().Be(caseNumber);
        KeyEnvelope.Parse(envelopeBefore)!.Server.Data.Should().Be(after.Server.Data);

        File.Delete(site.EnvelopePath);
        File.Delete(site.RootEnvelopePath);
        var missing = () => KeyToolCommands.Export(site, null, Path.Combine(_site, "export2"), null, new StringWriter());
        missing.Should().Throw<InvalidOperationException>().WithMessage("No evidence key envelope*");
        File.Exists(site.EnvelopePath).Should().BeFalse("the tool never makes a key");
    }
}
