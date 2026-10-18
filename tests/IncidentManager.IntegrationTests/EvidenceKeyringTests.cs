using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Evidence;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// PROD-57: the evidence key. It's protected by the integrity certificate already configured (or the CyberArk chain key),
/// kept in three envelope copies that restore one another, backed up to recovery certificates before any file is
/// encrypted, re-encrypted to a renewed certificate, and never replaced by a new key while files or an envelope need the
/// old one. A key that can't be opened pauses evidence (reads and writes refused, never written plain) and comes back
/// when its cause is fixed. Files are encrypted on disk, never readable there, and read back exactly.
/// </summary>
[Collection("CertificateStore")]
public sealed class EvidenceKeyringTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-evidence-key", Guid.NewGuid().ToString("N"));
    private readonly List<X509Certificate2> _installed = [];
    private TestDatabase _database;
    private readonly CapturingAudit _audit = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 17, 9, 0, 0, TimeSpan.Zero));

    public EvidenceKeyringTests()
    {
        Directory.CreateDirectory(_dir);
        Directory.CreateDirectory(Evidence);   // as start-up makes a fresh store's folder (PROD-56: never implicitly later)
        _database = OpenDatabase(TestDatabase.Sqlite);
    }

    private TestDatabase OpenDatabase(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(new HashChainService(), new TestCurrentUser(), _clock, new CaseChangeNotifier()));

    // A test that runs on each engine swaps the SQLite database for the one named.
    private void UseProvider(string provider)
    {
        if (provider == TestDatabase.Sqlite) return;
        _database.Dispose();
        _database = OpenDatabase(provider);
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
        _database.Dispose();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    // ---- helpers ----

    private static X509Certificate2 NewCertificate(string name)
    {
        using var rsa = RSA.Create(3072);
        using var made = new CertificateRequest($"CN={name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return X509CertificateLoader.LoadPkcs12(made.Export(X509ContentType.Pfx, "t"), "t", X509KeyStorageFlags.Exportable);
    }

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

    private void Uninstall(X509Certificate2 cert)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Remove(cert);
    }

    private string RecoveryCer(X509Certificate2 withKey)
    {
        var path = Path.Combine(_dir, $"recovery-{withKey.Thumbprint}.cer");
        File.WriteAllBytes(path, withKey.Export(X509ContentType.Cert));   // the public part only
        return path;
    }

    private string Evidence => Path.Combine(_dir, "evidence");
    private string Reports => Path.Combine(_dir, "reports");
    private string KeysFile => Path.Combine(_dir, "keys", "evidence-key.json");
    private string RootFile => Path.Combine(Evidence, ".key", "evidence-key.json");

    private readonly CapturingSecurityEventSink _siem = new();

    private EvidenceKeyring Ring(EvidenceEncryptionOptions options, SealSigningOptions? integrity = null, IChainKeyring? chain = null,
        IServiceScopeFactory? scopes = null) =>
        new(Options.Create(options), Options.Create(integrity ?? new SealSigningOptions { SigningKeyPath = Path.Combine(_dir, "keys", "seal-signing.pem") }),
            Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), Options.Create(new ReportOutputOptions { RootPath = Reports }),
            chain ?? NoChainKeys.Instance, scopes ?? Scopes(), siem: _siem);

    private IServiceScopeFactory Scopes(bool brokenDatabase = false)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IDbContextFactory<AppDbContext>>(new Factory(_database, brokenDatabase));
        services.AddSingleton<IAuditWriter>(_audit);
        return services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>();
    }

    private sealed class Factory(TestDatabase db, bool broken) : IDbContextFactory<AppDbContext>
    {
        public AppDbContext CreateDbContext() => broken ? throw new InvalidOperationException("The database can't be reached.") : db.NewContext();
    }

    private sealed class CapturingAudit : IAuditWriter
    {
        public List<string> Entries { get; } = [];
        public Task RecordAsync(AuditAction action, string entityType, string? entityId, string? caseNumber, string summary, CancellationToken ct = default)
        {
            Entries.Add($"{action} {entityType} {entityId}: {summary}");
            return Task.CompletedTask;
        }
    }

    private EvidenceEncryptionOptions On(X509Certificate2 server, params string[] recovery) => new()
    {
        Enabled = true, CertificateThumbprint = server.Thumbprint, StoreLocation = "CurrentUser", RecoveryCertificates = recovery,
    };

    private string? DbEnvelope()
    {
        using var db = _database.NewContext();
        return db.KeyEnvelopes.AsNoTracking().Select(r => r.EnvelopeJson).FirstOrDefault();
    }

    // ---- states ----

    [Fact]
    public async Task Off_unless_turned_on_and_not_configured_without_a_certificate_or_chain_key()
    {
        var off = Ring(new EvidenceEncryptionOptions());
        (await off.LoadAsync()).Should().Be(EvidenceKeyState.Off);
        EncryptedFiles.ForNewFile(off).Should().BeNull();

        var bare = Ring(new EvidenceEncryptionOptions { Enabled = true });
        (await bare.LoadAsync()).Should().Be(EvidenceKeyState.NotConfigured);
        bare.Problem.Should().Contain("integrity certificate");
        File.Exists(KeysFile).Should().BeFalse("no key is made without something to protect it");
    }

    [Fact]
    public async Task A_new_key_waits_for_a_backup_then_encrypts_and_a_recovery_certificate_opens_it()
    {
        var server = Installed("CaseBook evidence server");
        var ring = Ring(On(server));
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.NeedsBackup);
        ring.Problem.Should().Contain("No backup");
        EncryptedFiles.ForNewFile(ring).Should().BeNull("nothing is encrypted until a backup exists");
        File.Exists(KeysFile).Should().BeTrue();
        File.Exists(RootFile).Should().BeTrue();
        DbEnvelope().Should().NotBeNull();
        var envelope = KeyEnvelope.Parse(File.ReadAllText(KeysFile))!;
        File.ReadAllText(RootFile).Should().Be(File.ReadAllText(KeysFile));
        _audit.Entries.Should().ContainSingle(e => e.StartsWith("Create EvidenceKey", StringComparison.Ordinal));

        using var recovery = NewCertificate("CaseBook recovery (safe 1)");
        var ready = Ring(On(server, RecoveryCer(recovery)));
        (await ready.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        ready.CurrentKeyId.Should().Be(envelope.KeyId, "the same key, now with a backup");
        var copy = KeyEnvelope.Parse(File.ReadAllText(KeysFile))!.Recovery.Should().ContainSingle().Subject;
        var (recovered, _) = KeyWrap.Unpack(KeyWrap.FromCertificate(recovery, copy.Data));
        recovered.Should().Equal(ready.Key(envelope.KeyId), "the recovery certificate's private key alone opens the key");
        File.ReadAllText(KeysFile).Should().NotContain(Convert.ToBase64String(recovered), "no copy holds the key in the clear");
    }

    [Fact]
    public async Task Files_are_encrypted_on_disk_and_read_back_exactly_and_plain_files_still_read()
    {
        var server = Installed("CaseBook evidence server");
        using var recovery = NewCertificate("CaseBook recovery");
        var ring = Ring(On(server, RecoveryCer(recovery)));
        var plainStore = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }));
        var plain = await plainStore.SaveAsync(Guid.NewGuid(), new MemoryStream("written before encryption"u8.ToArray()));
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready);

        var store = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), ring);
        var bytes = RandomNumberGenerator.GetBytes(3 * Cbe1.ChunkSize + 99);
        var stored = await store.SaveAsync(Guid.NewGuid(), new MemoryStream(bytes));
        stored.SizeBytes.Should().Be(bytes.Length);
        stored.Sha256.Should().Be(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), "the hash is the original file's");
        var onDisk = await File.ReadAllBytesAsync(Path.Combine(Evidence, stored.StoragePath));
        Cbe1.IsCbe1(onDisk).Should().BeTrue();
        onDisk.AsSpan().IndexOf(bytes.AsSpan(0, 32)).Should().Be(-1, "nothing of the content is readable on disk");
        await using (var read = await store.OpenReadAsync(stored.StoragePath))
        {
            using var copy = new MemoryStream();
            await read.CopyToAsync(copy);
            copy.ToArray().Should().Equal(bytes);
        }
        await using (var old = await store.OpenReadAsync(plain.StoragePath))
            new StreamReader(old).ReadToEnd().Should().Be("written before encryption");

        var reports = new FileReportStore(Options.Create(new ReportOutputOptions { RootPath = Reports }), ring);
        var report = await reports.SaveAsync(Guid.NewGuid(), "Case report.docx", "report bytes"u8.ToArray());
        Cbe1.IsCbe1(await File.ReadAllBytesAsync(Path.Combine(Reports, report.StoragePath))).Should().BeTrue("reports are encrypted the same way");
        await using (var r = await reports.OpenReadAsync(report.StoragePath)) new StreamReader(r).ReadToEnd().Should().Be("report bytes");
        report.Sha256.Should().Be(Convert.ToHexString(SHA256.HashData("report bytes"u8)).ToLowerInvariant());
    }

    [Fact]
    public async Task A_malware_stand_in_is_never_readable_on_disk_and_comes_back_whole_and_zipped()
    {
        // The EICAR anti-malware test file, assembled here so this source file never holds it whole (antivirus would
        // quarantine the source or the build). Every antivirus product treats it as malware.
        var eicar = System.Text.Encoding.ASCII.GetBytes(string.Concat(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS", "-TEST-FILE!$H+H*"));
        var server = Installed("CaseBook evidence server");
        using var recovery = NewCertificate("CaseBook recovery");
        var ring = Ring(On(server, RecoveryCer(recovery)));
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        var store = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), ring);

        var stored = await store.SaveAsync(Guid.NewGuid(), new MemoryStream(eicar));
        var onDisk = await File.ReadAllBytesAsync(Path.Combine(Evidence, stored.StoragePath));
        onDisk.AsSpan().IndexOf("EICAR"u8).Should().Be(-1, "the sample is encrypted from the first byte, so antivirus on the server never sees it");
        Directory.GetFiles(Evidence, "*", SearchOption.AllDirectories).Where(f => !f.EndsWith("evidence-key.json", StringComparison.Ordinal))
            .Should().ContainSingle("no plain temporary copy is left (beside the stored file, only the key envelope)");
        EvidenceRisk.IsRisky("eicar.com", "application/octet-stream", eicar).Should().BeTrue("a .com is offered as a safe zip first");

        // Zipped as the safe download does it (EvidenceDownloadEndpoints): ZipCrypto, "infected", streamed from the store.
        using var zipped = new MemoryStream();
        await using (var content = await store.OpenReadAsync(stored.StoragePath))
        using (var zip = new ICSharpCode.SharpZipLib.Zip.ZipOutputStream(zipped) { IsStreamOwner = false, Password = EvidenceRisk.ZipPassword })
        {
            zip.SetLevel(1);
            zip.PutNextEntry(new ICSharpCode.SharpZipLib.Zip.ZipEntry(EvidenceRisk.EntryName("eicar.com")) { Size = eicar.Length, AESKeySize = 0 });
            await content.CopyToAsync(zip);
            zip.CloseEntry();
            zip.Finish();
        }
        zipped.ToArray().AsSpan().IndexOf("EICAR"u8).Should().Be(-1, "the zip doesn't carry the sample readable either");
        zipped.Position = 0;
        using var reader = new ICSharpCode.SharpZipLib.Zip.ZipFile(zipped) { Password = EvidenceRisk.ZipPassword };
        using var unzipped = new MemoryStream();
        using (var entry = reader.GetInputStream(reader[0])) await entry.CopyToAsync(unzipped);
        unzipped.ToArray().Should().Equal(eicar, "the analyst gets the sample exactly as recorded");
        Convert.ToHexString(SHA256.HashData(unzipped.ToArray())).ToLowerInvariant().Should().Be(stored.Sha256);
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Each_envelope_copy_restores_the_others_and_a_damaged_one_is_rewritten(string provider)
    {
        UseProvider(provider);   // the database copy (KeyEnvelopes) on the production engine too
        var server = Installed("CaseBook evidence server");
        using var recovery = NewCertificate("r");
        var options = On(server, RecoveryCer(recovery));
        var ring = Ring(options);
        await ring.LoadAsync();
        var keyId = ring.CurrentKeyId;

        File.Delete(KeysFile);
        (await Ring(options).LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        File.Exists(KeysFile).Should().BeTrue("restored from the database's copy");
        KeyEnvelope.Parse(File.ReadAllText(KeysFile))!.KeyId.Should().Be(keyId);

        File.Delete(KeysFile);
        await using (var db = _database.NewContext()) { db.KeyEnvelopes.RemoveRange(db.KeyEnvelopes); await db.SaveChangesAsync(); }
        var fromRoot = Ring(options);
        (await fromRoot.LoadAsync()).Should().Be(EvidenceKeyState.Ready, "the copy beside the evidence travels with it");
        fromRoot.CurrentKeyId.Should().Be(keyId);
        DbEnvelope().Should().NotBeNull();

        File.WriteAllText(KeysFile, "{ damaged");
        (await Ring(options).LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        KeyEnvelope.Parse(File.ReadAllText(KeysFile)).Should().NotBeNull("a damaged copy is rewritten from a good one");
        _audit.Entries.Count(e => e.StartsWith("Create", StringComparison.Ordinal)).Should().Be(1, "never a second key");
    }

    [Fact]
    public async Task A_missing_certificate_pauses_evidence_without_storing_anything_plain_and_its_return_resumes()
    {
        var server = Installed("CaseBook evidence server");
        using var recovery = NewCertificate("r");
        var options = On(server, RecoveryCer(recovery));
        var ring = Ring(options);
        await ring.LoadAsync();
        var store = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), ring);
        var stored = await store.SaveAsync(Guid.NewGuid(), new MemoryStream("sample"u8.ToArray()));

        var pfx = server.Export(X509ContentType.Pfx, "t");
        Uninstall(server);
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Unavailable);
        ring.Problem.Should().Contain("can't be opened").And.Contain("casebook-keytool recover");
        var read = () => store.OpenReadAsync(stored.StoragePath);
        await read.Should().ThrowAsync<EvidenceKeyUnavailableException>();
        var write = () => store.SaveAsync(Guid.NewGuid(), new MemoryStream("new"u8.ToArray()));
        await write.Should().ThrowAsync<EvidenceKeyUnavailableException>("refused, never stored unencrypted");
        Directory.GetFiles(Evidence, "*.bin", SearchOption.AllDirectories).Should().ContainSingle();

        var back = X509CertificateLoader.LoadPkcs12(pfx, "t", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);
        using (var s = new X509Store(StoreName.My, StoreLocation.CurrentUser)) { s.Open(OpenFlags.ReadWrite); s.Add(back); }
        _installed.Add(back);
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready, "the next check clears it, no restart");
        await using var again = await store.OpenReadAsync(stored.StoragePath);
        new StreamReader(again).ReadToEnd().Should().Be("sample");
    }

    // ---- PROD-59: the key in the SIEM, and what the keytool did in the audit trail ----

    [Fact]
    public async Task The_SIEM_hears_the_key_made_lost_and_back_once_each()
    {
        var server = Installed("CaseBook evidence server");
        using var recovery = NewCertificate("r");
        var options = On(server, RecoveryCer(recovery));
        var ring = Ring(options);
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        _siem.Events.Should().ContainSingle(e => e.EventId == SecurityEventIds.EvidenceKeyChanged && e.Action == "KeyCreated")
            .Which.TargetId.Should().Be(ring.CurrentKeyId);

        var pfx = server.Export(X509ContentType.Pfx, "t");
        Uninstall(server);
        await ring.LoadAsync();
        await ring.LoadAsync();   // a 5-minute retry
        _siem.Events.Should().ContainSingle(e => e.EventId == SecurityEventIds.EvidenceKeyUnavailable, "once per episode")
            .Which.Severity.Should().Be(SecuritySeverity.High);

        var back = X509CertificateLoader.LoadPkcs12(pfx, "t", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);
        using (var s = new X509Store(StoreName.My, StoreLocation.CurrentUser)) { s.Open(OpenFlags.ReadWrite); s.Add(back); }
        _installed.Add(back);
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        _siem.Events.Should().ContainSingle(e => e.Action == "KeyAvailable");
        _siem.Events.Select(e => e.Detail ?? "").Should().NotContain(d => d.Contains("BEGIN", StringComparison.Ordinal), "no key material");
    }

    [Fact]
    public async Task What_the_keytool_did_reaches_the_audit_trail_and_the_SIEM_once()
    {
        var server = Installed("CaseBook evidence server");
        using var recovery = NewCertificate("r");
        var options = On(server, RecoveryCer(recovery));
        (await Ring(options).LoadAsync()).Should().Be(EvidenceKeyState.Ready);

        // casebook-keytool, run on the server: a drill, an export of one case, a recovery. It writes the keys folder's copy.
        var e = KeyEnvelope.Parse(await File.ReadAllTextAsync(KeysFile))!;
        e.Record(KeyToolRecord.Drill, "Recovery drill: evidence key opens with 3 shares.");
        e.Record(KeyToolRecord.Exported, "Exported 2 evidence file(s) decrypted (case 2026-01) to E:\\out; manifest.csv SHA-256 abc.", "2026-01");
        e.Record(KeyToolRecord.Recovered, "Evidence key recovered onto certificate 1234.");
        await File.WriteAllTextAsync(KeysFile, e.ToJson());

        var ring = Ring(options);
        await ring.LoadAsync();
        _audit.Entries.Should().Contain(x => x.StartsWith("Export EvidenceKey", StringComparison.Ordinal) && x.Contains("manifest.csv SHA-256 abc", StringComparison.Ordinal));
        _audit.Entries.Count(x => x.Contains("casebook-keytool, run by", StringComparison.Ordinal)).Should().Be(3);
        _siem.Events.Should().ContainSingle(x => x.EventId == SecurityEventIds.EvidenceExportedOffline).Which.CaseNumber.Should().Be("2026-01");
        _siem.Events.Should().ContainSingle(x => x.Action == "RecoveryDrill");
        _siem.Events.Should().ContainSingle(x => x.Action == "KeyRecovered").Which.Severity.Should().Be(SecuritySeverity.High);
        KeyEnvelope.Parse(DbEnvelope())!.Records.Should().HaveCount(3, "the database copy now holds them, so they're recorded once");

        await ring.LoadAsync();
        await Ring(options).LoadAsync();   // and after a restart
        _audit.Entries.Count(x => x.Contains("casebook-keytool, run by", StringComparison.Ordinal)).Should().Be(3);
        _siem.Events.Count(x => x.EventId == SecurityEventIds.EvidenceExportedOffline).Should().Be(1);
    }

    // ---- review findings (2026-10-17) ----

    [Fact]
    public async Task A_stale_copy_doesnt_erase_the_record_of_a_backup(/* review finding 1 */)
    {
        var server = Installed("CaseBook evidence server");
        var options = On(server);   // no recovery certificate: the shares are the only backup
        (await Ring(options).LoadAsync()).Should().Be(EvidenceKeyState.NeedsBackup);
        var stale = await File.ReadAllTextAsync(KeysFile);

        // casebook-keytool split recorded the shares (and a drill) in the keys folder; CaseBook copied that everywhere.
        var issued = KeyEnvelope.Parse(stale)!;
        issued.Shares = new SharesIssued { IssuedUtc = DateTimeOffset.UtcNow, Threshold = 3, Count = 5 };
        (issued.LastDrillUtc, issued.LastDrillBy) = (DateTimeOffset.UtcNow, "custodian");
        await File.WriteAllTextAsync(KeysFile, issued.ToJson());
        (await Ring(options).LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        KeyEnvelope.Parse(DbEnvelope())!.Shares.Should().NotBeNull();

        // The keys folder is restored from a backup made before that.
        await File.WriteAllTextAsync(KeysFile, stale);
        var ring = Ring(options);
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready, "the other copies' record of the shares is kept: files stay encrypted");
        KeyEnvelope.Parse(await File.ReadAllTextAsync(KeysFile))!.Shares.Should().NotBeNull("and written back over the stale copy");
        ring.Health!.LastDrillUtc.Should().NotBeNull();
        _audit.Entries.Should().Contain(e => e.Contains("kept the record of shares issued", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_database_row_for_another_key_doesnt_hide_this_ones_and_a_reload_keeps_the_same_key(/* findings 5 and 7 */)
    {
        var server = Installed("CaseBook evidence server");
        using var recovery = NewCertificate("r");
        var options = On(server, RecoveryCer(recovery));
        var ring = Ring(options);
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        var keyId = ring.CurrentKeyId!;
        var held = ring.Key(keyId)!;
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        ring.Key(keyId).Should().BeSameAs(held, "the daily check keeps the array a save in progress may hold");
        held.Should().Contain(b => b != 0, "and doesn't zero it");

        // A newer row for some other key (a restore merged in, say), and the two file copies gone.
        var foreign = KeyEnvelope.Parse(await File.ReadAllTextAsync(KeysFile))!;
        foreign.KeyId = "0123456789abcdef";
        await using (var db = new AppDbContext(_database.OptionsWithoutInterceptors))
        {
            db.KeyEnvelopes.Add(new IncidentManager.Domain.Entities.KeyEnvelopeRecord { KeyId = foreign.KeyId, EnvelopeJson = foreign.ToJson(), UpdatedAtUtc = DateTimeOffset.UtcNow.AddDays(1) });
            await db.SaveChangesAsync();
        }
        File.Delete(KeysFile);
        File.Delete(RootFile);
        var again = Ring(options);
        (await again.LoadAsync()).Should().Be(EvidenceKeyState.Ready, "this key's own row still opens");
        again.CurrentKeyId.Should().Be(keyId);
    }

    [Fact]
    public async Task The_check_before_a_new_key_reads_past_hundreds_of_plain_files_and_fails_closed(/* review finding 3 */)
    {
        var server = Installed("CaseBook evidence server");
        using var recovery = NewCertificate("r");
        var options = On(server, RecoveryCer(recovery));
        var ring = Ring(options);
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        var keyId = ring.CurrentKeyId!;
        var store = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), ring);
        var encrypted = await store.SaveAsync(Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff"), new MemoryStream(new byte[5000]));
        // 600 plain files ahead of it (a store part-way through conversion): the old check gave up after 500 and said none.
        var plain = Path.Combine(Evidence, "00000000000000000000000000000000");
        Directory.CreateDirectory(plain);
        for (var i = 0; i < 600; i++) await File.WriteAllBytesAsync(Path.Combine(plain, $"{i:D4}.bin"), new byte[300]);

        // Every envelope copy is lost.
        File.Delete(KeysFile);
        File.Delete(RootFile);
        await using (var db = _database.NewContext()) { db.KeyEnvelopes.RemoveRange(db.KeyEnvelopes); await db.SaveChangesAsync(); }
        var after = Ring(options);
        (await after.LoadAsync()).Should().Be(EvidenceKeyState.Unavailable);
        after.Problem.Should().Contain(keyId).And.Contain("No new key was made");

        // A check that can't finish isn't "no encrypted files" either.
        File.Delete(Path.Combine(Evidence, encrypted.StoragePath));
        var limit = EvidenceKeyring.ScanTimeLimit;
        try
        {
            EvidenceKeyring.ScanTimeLimit = TimeSpan.FromTicks(1);
            var slow = Ring(options);
            (await slow.LoadAsync()).Should().Be(EvidenceKeyState.Unavailable);
            slow.Problem.Should().Contain("unknown").And.Contain("No new key was made");
        }
        finally { EvidenceKeyring.ScanTimeLimit = limit; }
        File.Exists(KeysFile).Should().BeFalse();

        // Nor is a store whose folder isn't there.
        Directory.Delete(Evidence, recursive: true);
        var gone = Ring(options);
        (await gone.LoadAsync()).Should().Be(EvidenceKeyState.Unavailable);
        gone.Problem.Should().Contain("isn't there");
    }

    [Fact]
    public async Task A_missing_or_removed_protection_reports_rather_than_stopping_start_up_or_storing_plain(/* findings 6 and 10 */)
    {
        using var recovery = NewCertificate("r");
        var typo = new EvidenceEncryptionOptions
        {
            Enabled = true, CertificateThumbprint = "00112233445566778899AABBCCDDEEFF00112233", StoreLocation = "CurrentUser",
            RecoveryCertificates = [RecoveryCer(recovery)],
        };
        var first = Ring(typo);
        (await first.LoadAsync()).Should().Be(EvidenceKeyState.Unavailable, "a mistyped thumbprint at first enablement doesn't throw");
        first.Problem.Should().Contain("none was made");
        File.Exists(KeysFile).Should().BeFalse();

        // Encryption was on; then the setting that protected the key is taken away.
        var server = Installed("CaseBook evidence server");
        (await Ring(On(server, RecoveryCer(recovery))).LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        var removed = Ring(new EvidenceEncryptionOptions { Enabled = true, RecoveryCertificates = [RecoveryCer(recovery)] });
        (await removed.LoadAsync()).Should().Be(EvidenceKeyState.Unavailable, "not NotConfigured: nothing new is stored unencrypted");
        removed.Problem.Should().Contain("no certificate or chain key is configured");
    }

    [Fact]
    public async Task A_header_naming_no_proper_key_is_a_damaged_file_never_served_raw(/* review finding 11 */)
    {
        var server = Installed("CaseBook evidence server");
        using var recovery = NewCertificate("r");
        var ring = Ring(On(server, RecoveryCer(recovery)));
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        var store = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), ring);
        var stored = await store.SaveAsync(Guid.NewGuid(), new MemoryStream("sample"u8.ToArray()));
        var path = Path.Combine(Evidence, stored.StoragePath);
        var bytes = await File.ReadAllBytesAsync(path);
        bytes[5] = (byte)'\n';   // the key id's first character
        await File.WriteAllBytesAsync(path, bytes);
        Cbe1.KeyIdOf(bytes).Should().BeNull();
        var read = () => store.OpenReadAsync(stored.StoragePath);
        await read.Should().ThrowAsync<CryptographicException>();
    }

    [Fact]
    public async Task A_key_that_cant_be_opened_at_start_up_logs_its_alarm_on_the_first_load()
    {
        // Found on the dev server: before its first load the keyring reads Unavailable, so a key unavailable from start-up
        // changed no state and logged nothing. The first load always logs.
        var server = Installed("CaseBook evidence server");
        using var recovery = NewCertificate("r");
        var options = On(server, RecoveryCer(recovery));
        await Ring(options).LoadAsync();   // makes the key and its envelope
        Uninstall(server);

        var log = new ListLogger();
        var restarted = new EvidenceKeyring(Options.Create(options),
            Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(_dir, "keys", "seal-signing.pem") }),
            Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), Options.Create(new ReportOutputOptions { RootPath = Reports }),
            NoChainKeys.Instance, Scopes(), log);
        (await restarted.LoadAsync()).Should().Be(EvidenceKeyState.Unavailable);
        log.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical).Which.Message.Should().Contain("can't be opened");
        await restarted.LoadAsync();
        log.Entries.Should().ContainSingle(e => e.Level == LogLevel.Critical, "once per change, not every 5-minute check");
    }

    private sealed class ListLogger : ILogger<EvidenceKeyring>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }

    [Fact]
    public async Task No_new_key_is_made_while_files_or_an_unreadable_database_might_need_the_old_one()
    {
        var server = Installed("CaseBook evidence server");
        using var recovery = NewCertificate("r");
        var options = On(server, RecoveryCer(recovery));
        var ring = Ring(options);
        await ring.LoadAsync();
        var store = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), ring);
        await store.SaveAsync(Guid.NewGuid(), new MemoryStream("sample"u8.ToArray()));

        // Every envelope copy lost, but a file needs the key: no new key.
        File.Delete(KeysFile);
        File.Delete(RootFile);
        await using (var db = _database.NewContext()) { db.KeyEnvelopes.RemoveRange(db.KeyEnvelopes); await db.SaveChangesAsync(); }
        var lost = Ring(options);
        (await lost.LoadAsync()).Should().Be(EvidenceKeyState.Unavailable);
        lost.Problem.Should().Contain($"encrypted with evidence key {ring.CurrentKeyId}").And.Contain("No new key was made");
        File.Exists(KeysFile).Should().BeFalse();

        // A database that can't be read can't show there's no key: no new key either.
        foreach (var f in Directory.GetFiles(Evidence, "*.bin", SearchOption.AllDirectories)) File.Delete(f);
        var blind = Ring(options, scopes: Scopes(brokenDatabase: true));
        (await blind.LoadAsync()).Should().Be(EvidenceKeyState.Unavailable);
        blind.Problem.Should().Contain("database couldn't be read");
        File.Exists(KeysFile).Should().BeFalse();
        _audit.Entries.Count(e => e.StartsWith("Create", StringComparison.Ordinal)).Should().Be(1);
    }

    [Fact]
    public async Task A_renewed_certificate_gets_the_key_re_encrypted_to_it()
    {
        var old = Installed("CaseBook evidence server (2026)");
        using var recovery = NewCertificate("r");
        var ring = Ring(On(old, RecoveryCer(recovery)));
        await ring.LoadAsync();
        var keyId = ring.CurrentKeyId;

        var renewed = Installed("CaseBook evidence server (2027)");
        var after = Ring(On(renewed, RecoveryCer(recovery)));
        (await after.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        after.CurrentKeyId.Should().Be(keyId);
        KeyEnvelope.Parse(File.ReadAllText(KeysFile))!.Server.Ref.Should().Be(CertificateLookup.Normalize(renewed.Thumbprint));
        _audit.Entries.Should().Contain(e => e.Contains("re-encrypted to certificate", StringComparison.Ordinal));

        Uninstall(old);
        (await Ring(On(renewed, RecoveryCer(recovery))).LoadAsync()).Should().Be(EvidenceKeyState.Ready, "the old certificate is no longer needed");
    }

    [Fact]
    public async Task With_the_chain_key_from_CyberArk_the_key_is_protected_by_it_and_recovery_carries_both()
    {
        var chain = new OneChainKey();
        var integrity = new SealSigningOptions
        {
            SigningKeyPath = Path.Combine(_dir, "keys", "seal-signing.pem"),
            ChainKey = new ChainKeyOptions { Enabled = true, Source = ChainKeySource.CyberArk },
        };
        using var recovery = NewCertificate("r");
        var options = new EvidenceEncryptionOptions { Enabled = true, RecoveryCertificates = [RecoveryCer(recovery)] };
        var ring = Ring(options, integrity, chain);
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        var envelope = KeyEnvelope.Parse(File.ReadAllText(KeysFile))!;
        envelope.Server.Kind.Should().Be(WrappedKey.ChainKey);
        envelope.Server.Ref.Should().Be(chain.CurrentKeyId);
        var (ek, ck) = KeyWrap.Unpack(KeyWrap.FromCertificate(recovery, envelope.Recovery.Single().Data));
        ek.Should().Equal(ring.Key(ring.CurrentKeyId!));
        ck.Should().Equal(chain.Key(chain.CurrentKeyId!), "a recovery certificate restores the chain key too");
        (await Ring(options, integrity, new OneChainKey()).LoadAsync()).Should().Be(EvidenceKeyState.Unavailable, "another chain key opens nothing");
    }

    [Fact]
    public async Task Files_stored_before_are_converted_only_if_they_match_their_record_and_a_busy_one_waits()
    {
        await using (var ctx = _database.NewContext()) await DevDataSeeder.SeedAsync(ctx, _clock);
        Guid caseId;
        await using (var ctx = _database.NewContext()) caseId = (await ctx.Cases.FirstAsync()).Id;
        var plainStore = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }));
        var plainReports = new FileReportStore(Options.Create(new ReportOutputOptions { RootPath = Reports }));
        var good = await plainStore.SaveAsync(caseId, new MemoryStream("intact sample"u8.ToArray()));
        var tampered = await plainStore.SaveAsync(caseId, new MemoryStream("original"u8.ToArray()));
        var busy = await plainStore.SaveAsync(caseId, new MemoryStream("in use"u8.ToArray()));
        var report = await plainReports.SaveAsync(caseId, "report.docx", "report"u8.ToArray());
        await using (var raw = new AppDbContext(_database.OptionsWithoutInterceptors))
        {
            foreach (var (s, name) in new[] { (good, "good.exe"), (tampered, "tampered.bin"), (busy, "busy.bin") })
                raw.Evidence.Add(new IncidentManager.Domain.Entities.Evidence
                {
                    CaseId = caseId, OriginalFileName = name, ContentType = "", SizeBytes = s.SizeBytes, Sha256 = s.Sha256,
                    StoragePath = s.StoragePath, CreatedBy = "seed", CreatedAtUtc = _clock.UtcNow,
                });
            raw.Reports.Add(new IncidentManager.Domain.Entities.Report
            {
                CaseId = caseId, Version = 1, FileName = "report.docx", StoragePath = report.StoragePath, ContentSha256 = report.Sha256,
                CreatedBy = "seed", CreatedAtUtc = _clock.UtcNow,
            });
            await raw.SaveChangesAsync();
        }
        await File.WriteAllTextAsync(Path.Combine(Evidence, tampered.StoragePath), "changed!");

        var server = Installed("CaseBook evidence server");
        using var recovery = NewCertificate("r");
        var ring = Ring(On(server, RecoveryCer(recovery)));
        await ring.LoadAsync();
        var status = new EvidenceConversionStatus();
        var conversion = new EvidenceConversion(Scopes(), ring, Options.Create(new EvidenceStoreOptions { RootPath = Evidence }),
            Options.Create(new ReportOutputOptions { RootPath = Reports }), new IncidentManager.Application.Integrity.EvidenceFileGate(), status);

        int converted;
        await using (new FileStream(Path.Combine(Evidence, busy.StoragePath), FileMode.Open, FileAccess.Read, FileShare.None))
            converted = await conversion.RunAsync(100);
        converted.Should().Be(2, "the intact file and the report");
        status.Mismatched.Should().Be(1);
        status.Busy.Should().Be(1);
        status.Remaining.Should().Be(1, "the busy file waits for the next run");
        Cbe1.IsCbe1(await File.ReadAllBytesAsync(Path.Combine(Evidence, good.StoragePath))).Should().BeTrue();
        Cbe1.IsCbe1(await File.ReadAllBytesAsync(Path.Combine(Reports, report.StoragePath))).Should().BeTrue();
        (await File.ReadAllTextAsync(Path.Combine(Evidence, tampered.StoragePath))).Should().Be("changed!", "never vouched for by encryption");
        var store = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), ring);
        await using (var read = await store.OpenReadAsync(good.StoragePath)) new StreamReader(read).ReadToEnd().Should().Be("intact sample");
        _audit.Entries.Should().Contain(e => e.Contains("2 stored evidence file(s) and report(s) encrypted at rest", StringComparison.Ordinal));

        (await conversion.RunAsync(100)).Should().Be(1, "the file no longer in use");
        status.Remaining.Should().Be(0);
        Directory.GetFiles(_dir, "*.cbe1", SearchOption.AllDirectories).Should().BeEmpty("no temporary copies are left");
    }

    [Fact]
    public void A_store_wide_finding_stays_through_re_check_runs_until_cleared_and_alarms_once()
    {
        var monitor = new IncidentManager.Application.Integrity.EvidenceIntegrityMonitor();
        monitor.RecordCondition(IncidentManager.Application.Integrity.EvidenceDriftKind.KeyUnavailable, "certificate missing", _clock.UtcNow)
            .Should().BeTrue();
        monitor.RecordCondition(IncidentManager.Application.Integrity.EvidenceDriftKind.KeyUnavailable, "certificate missing", _clock.UtcNow)
            .Should().BeFalse("once per episode");
        monitor.RecordResult(new IncidentManager.Application.Integrity.EvidenceVerificationResult(3, [], _clock.UtcNow), _clock.UtcNow)
            .Should().BeFalse();
        monitor.Current!.Drifts.Should().ContainSingle(d => d.Kind == IncidentManager.Application.Integrity.EvidenceDriftKind.KeyUnavailable,
            "a clean re-check of plain files doesn't clear it");
        monitor.RecordCondition(IncidentManager.Application.Integrity.EvidenceDriftKind.KeyUnavailable, null, _clock.UtcNow).Should().BeFalse();
        monitor.Current.IsClean.Should().BeTrue();
        monitor.RecordCondition(IncidentManager.Application.Integrity.EvidenceDriftKind.KeyUnavailable, "again", _clock.UtcNow)
            .Should().BeTrue("a new episode alarms again");
    }

    private sealed class OneChainKey : IChainKeyring
    {
        private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
        public string? CurrentKeyId => ChainKeyring.KeyIdOf(_key);
        public byte[]? Key(string keyId) => keyId == CurrentKeyId ? _key : null;
        public IReadOnlyList<string> KeyIds => [CurrentKeyId!];
        public string? Source => "test";
    }

    [Fact]
    public async Task A_large_upload_is_encrypted_part_by_part_and_recorded_exactly()
    {
        var server = Installed("CaseBook evidence server");
        using var recovery = NewCertificate("r");
        var ring = Ring(On(server, RecoveryCer(recovery)));
        await ring.LoadAsync();
        var store = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), ring);
        await using (var ctx = _database.NewContext()) await DevDataSeeder.SeedAsync(ctx, _clock);
        Guid caseId;
        await using (var ctx = _database.NewContext()) caseId = (await ctx.Cases.FirstAsync()).Id;
        var user = new TestCurrentUser { RoleSet = [AppRole.IncidentCommander] };
        var svc = new EvidenceService(_database.Factory(), store, user, _clock, new NoOpAuditWriter(),
            new TestOptionsMonitor<EvidenceStorageOptions>(new EvidenceStorageOptions { MinFreeSpaceGB = 0 }), new EvidenceUploadSessions());
        var bytes = RandomNumberGenerator.GetBytes(EvidenceUploadSessions.PartBytes + 70_000);

        var started = await svc.BeginUploadAsync(caseId, "memory.dmp", "", bytes.Length, null);
        await svc.AppendPartAsync(started.Id, 0, bytes.AsMemory(0, EvidenceUploadSessions.PartBytes));
        var part = Directory.GetFiles(Path.Combine(Evidence, ".incoming"), "*.part").Single();
        Cbe1.IsCbe1(await File.ReadAllBytesAsync(part)).Should().BeTrue("the parts are encrypted as they arrive");
        await svc.AppendPartAsync(started.Id, 1, bytes.AsMemory(EvidenceUploadSessions.PartBytes));
        var recorded = await svc.CompleteUploadAsync(started.Id);
        (await svc.CompleteUploadAsync(started.Id)).Id.Should().Be(recorded.Id);

        recorded.Sha256.Should().Be(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
        await using var read = await store.OpenReadAsync(recorded.StoragePath);
        using var copy = new MemoryStream();
        await read.CopyToAsync(copy);
        copy.ToArray().Should().Equal(bytes);
    }

    [Fact]
    public async Task An_encrypted_upload_resumes_after_a_restart_and_reads_back_whole(/* PROD-59 */)
    {
        var server = Installed("CaseBook evidence server");
        using var recovery = NewCertificate("r");
        var ring = Ring(On(server, RecoveryCer(recovery)));
        await ring.LoadAsync();
        var store = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), ring);
        await using (var ctx = _database.NewContext()) await DevDataSeeder.SeedAsync(ctx, _clock);
        Guid caseId;
        await using (var ctx = _database.NewContext()) caseId = (await ctx.Cases.FirstAsync()).Id;
        var user = new TestCurrentUser { RoleSet = [AppRole.IncidentCommander] };
        var limits = new TestOptionsMonitor<EvidenceStorageOptions>(new EvidenceStorageOptions { MinFreeSpaceGB = 0 });
        var bytes = RandomNumberGenerator.GetBytes(2 * EvidenceUploadSessions.PartBytes + 70_000);
        var sample = Convert.ToHexString(SHA256.HashData(bytes.AsSpan(0, 1024 * 1024))).ToLowerInvariant();
        var before = new EvidenceService(_database.Factory(), store, user, _clock, new NoOpAuditWriter(), limits, new EvidenceUploadSessions());
        var started = await before.BeginUploadAsync(caseId, "memory.dmp", "", bytes.Length, null, sample);
        await before.AppendPartAsync(started.Id, 0, bytes.AsMemory(0, EvidenceUploadSessions.PartBytes));

        // The app restarts: a new keyring (the same key, from its envelope), a new store, sessions put back from disk.
        var ring2 = Ring(On(server, RecoveryCer(recovery)));
        (await ring2.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        var store2 = new FileEvidenceStore(Options.Create(new EvidenceStoreOptions { RootPath = Evidence }), ring2);
        var uploads = new EvidenceUploadSessions();
        (await EvidenceService.RestoreUploadsAsync(uploads, store2)).Should().Be(1);
        var after = new EvidenceService(_database.Factory(), store2, user, _clock, new NoOpAuditWriter(), limits, uploads);
        (await after.ResumeUploadAsync(started.Id, "memory.dmp", bytes.Length, sample)).NextPart.Should().Be(1);
        await after.AppendPartAsync(started.Id, 1, bytes.AsMemory(EvidenceUploadSessions.PartBytes, EvidenceUploadSessions.PartBytes));
        await after.AppendPartAsync(started.Id, 2, bytes.AsMemory(2 * EvidenceUploadSessions.PartBytes));
        var recorded = await after.CompleteUploadAsync(started.Id);

        recorded.Sha256.Should().Be(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
        Cbe1.IsCbe1(await File.ReadAllBytesAsync(Path.Combine(Evidence, recorded.StoragePath))).Should().BeTrue();
        await using var read = await store2.OpenReadAsync(recorded.StoragePath);
        using var copy = new MemoryStream();
        await read.CopyToAsync(copy);
        copy.ToArray().Should().Equal(bytes, "parts written before and after the restart make one whole encrypted file");
    }
}
