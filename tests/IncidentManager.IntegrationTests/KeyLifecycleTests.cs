using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using IncidentManager.KeyTool;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// casebook-keytool's key changes: rotate-signing-key keeps the old key's public half where the app reads it and makes a
/// new key; enable-chain-key checks the certificate and waits for the backup before writing the settings; retire-custodian
/// takes a recovery certificate out of the settings and the envelope, records it, and won't remove the last backup.
/// </summary>
[Collection("CertificateStore")]
public sealed class KeyLifecycleTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "im-keylife", Guid.NewGuid().ToString("N"));
    private readonly List<X509Certificate2> _installed = [];

    private string SiteFolder => Path.Combine(_root, "site");
    private string Keys => Path.Combine(_root, "data", "keys");
    private string Evidence => Path.Combine(_root, "data", "evidence-store");
    private string SettingsFile => Path.Combine(SiteFolder, "appsettings.Production.json");

    public KeyLifecycleTests()
    {
        Directory.CreateDirectory(SiteFolder);
        Directory.CreateDirectory(Keys);
        Directory.CreateDirectory(Evidence);
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
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { /* best effort */ }
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

    private void WriteSettings(object integrity, object? storage = null) =>
        File.WriteAllText(SettingsFile, System.Text.Json.JsonSerializer.Serialize(new
        {
            Database = new { Provider = "Sqlite" },
            EvidenceStore = new { RootPath = Evidence },
            Integrity = integrity,
            Storage = storage,
        }));

    [Fact]
    public void Rotate_signing_key_saves_the_old_public_half_where_the_app_reads_it_and_makes_a_new_key()
    {
        var current = Path.Combine(Keys, "seal-signing.pem");
        var oldId = SigningKeyCommands.NewKey(current, new StringWriter());
        WriteSettings(new { SigningKeyPath = current });
        var site = Site.Load(SiteFolder);

        var output = new StringWriter();
        var newId = KeyLifecycleCommands.RotateSigningKey(site, Path.Combine(_root, "out", "new-signing.pem"), null, () => "", output);

        newId.Should().NotBe(oldId);
        var retired = Path.Combine(Keys, "retired", $"{oldId}.pem");
        File.ReadAllText(retired).Should().Contain("BEGIN PUBLIC KEY", "the public half only");
        File.Exists(Path.Combine(_root, "out", "new-signing.pem")).Should().BeTrue();
        output.ToString().Should().Contain(newId).And.Contain("re-verify an older seal");
        File.ReadAllText(SettingsFile).Should().NotContain("new-signing", "the settings are the administrator's to change");

        // A PFX for the certificate store: the key it holds is the new key.
        var pfx = Path.Combine(_root, "out", "new-signing.pfx");
        var pfxId = KeyLifecycleCommands.RotateSigningKey(Site.Load(SiteFolder), null, pfx, () => "pfx-pass", new StringWriter());
        using (var inPfx = X509CertificateLoader.LoadPkcs12FromFile(pfx, "pfx-pass", X509KeyStorageFlags.EphemeralKeySet))
        using (var key = inPfx.GetRSAPublicKey()!)
            IncidentManager.Infrastructure.Security.RsaSealSigner.KeyIdOf(key).Should().Be(pfxId);

        var neither = () => KeyLifecycleCommands.RotateSigningKey(site, null, null, () => "", new StringWriter());
        neither.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Enable_chain_key_checks_the_certificate_waits_for_the_backup_then_writes_the_settings()
    {
        var cert = Installed("CaseBook chain key");
        WriteSettings(new
        {
            SigningKeyPath = Path.Combine(Keys, "seal-signing.pem"),
            ChainKey = new { WrappedKeyPath = Path.Combine(Keys, "chain-key.json"), RetiredWrappedKeysPath = Path.Combine(Keys, "chain-retired") },
        });
        var before = File.ReadAllText(SettingsFile);

        var unconfirmed = () => KeyLifecycleCommands.EnableChainKey(Site.Load(SiteFolder), cert.Thumbprint, "CurrentUser", false, new StringWriter());
        unconfirmed.Should().Throw<ChainKeyNotConfirmedException>();
        File.ReadAllText(SettingsFile).Should().Be(before, "nothing changes until the backup is confirmed");

        var output = new StringWriter();
        KeyLifecycleCommands.EnableChainKey(Site.Load(SiteFolder), cert.Thumbprint, "CurrentUser", true, output);
        var chain = JsonNode.Parse(File.ReadAllText(SettingsFile))!["Integrity"]!["ChainKey"]!;
        chain["Enabled"]!.GetValue<bool>().Should().BeTrue();
        chain["Source"]!.GetValue<string>().Should().Be("Certificate");
        chain["CertificateThumbprint"]!.GetValue<string>().Should().Be(CertificateLookup.Normalize(cert.Thumbprint));
        chain["WrappedKeyPath"]!.GetValue<string>().Should().Be(Path.Combine(Keys, "chain-key.json"), "the rest of the section is kept");
        Directory.GetFiles(SiteFolder, "appsettings.Production.json.before-enable-chain-key-*").Should().ContainSingle();

        var again = () => KeyLifecycleCommands.EnableChainKey(Site.Load(SiteFolder), cert.Thumbprint, "CurrentUser", true, new StringWriter());
        again.Should().Throw<InvalidOperationException>().WithMessage("*already on*");
    }

    [Fact]
    public void Enable_chain_key_refuses_a_key_file_inside_the_site_folder()
    {
        var cert = Installed("CaseBook chain key (site)");
        WriteSettings(new { SigningKeyPath = Path.Combine(SiteFolder, "App_Data", "keys", "seal-signing.pem") });
        var inside = () => KeyLifecycleCommands.EnableChainKey(Site.Load(SiteFolder), cert.Thumbprint, "CurrentUser", true, new StringWriter());
        inside.Should().Throw<InvalidOperationException>().WithMessage("*inside the site folder*");
    }

    [Fact]
    public async Task Retire_custodian_removes_their_lock_and_records_it_but_never_the_last_backup()
    {
        var server = Installed("CaseBook evidence server");
        string Cer(string name)
        {
            using var rsa = RSA.Create(3072);
            using var made = new CertificateRequest($"CN={name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
                .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
            var path = Path.Combine(Keys, $"{name}.cer");
            File.WriteAllBytes(path, made.Export(X509ContentType.Cert));
            return path;
        }
        var a = Cer("custodian-a");
        var b = Cer("custodian-b");
        object Storage(params string[] recovery) =>
            new { Encryption = new { Enabled = true, CertificateThumbprint = server.Thumbprint, StoreLocation = "CurrentUser", RecoveryCertificates = recovery } };
        WriteSettings(new { SigningKeyPath = Path.Combine(Keys, "seal-signing.pem") }, Storage(a, b));
        var site = Site.Load(SiteFolder);
        var ring = new EvidenceKeyring(
            Options.Create(new EvidenceEncryptionOptions { Enabled = true, CertificateThumbprint = server.Thumbprint, StoreLocation = "CurrentUser", RecoveryCertificates = [a, b] }),
            Options.Create(site.Integrity), Options.Create(new EvidenceStoreOptions { RootPath = Evidence }),
            Options.Create(new ReportOutputOptions { RootPath = Path.Combine(_root, "data", "reports") }), NoChainKeys.Instance);
        (await ring.LoadAsync()).Should().Be(EvidenceKeyState.Ready);
        KeyEnvelope.Parse(File.ReadAllText(site.EnvelopePath))!.Recovery.Should().HaveCount(2);

        var thumbA = X509CertificateLoader.LoadCertificateFromFile(a).Thumbprint;
        KeyLifecycleCommands.RetireCustodian(site, thumbA, "pfx and envelope copy collected and shredded", new StringWriter());

        var envelope = KeyEnvelope.Parse(File.ReadAllText(site.EnvelopePath))!;
        envelope.Recovery.Should().ContainSingle().Which.Subject.Should().Be("CN=custodian-b");
        envelope.Records.Should().Contain(r => r.Kind == KeyToolRecord.CustodianRetired && r.Summary.Contains("shredded"));
        JsonNode.Parse(File.ReadAllText(SettingsFile))!["Storage"]!["Encryption"]!["RecoveryCertificates"]!.AsArray()
            .Select(n => n!.GetValue<string>()).Should().Equal(b);

        var thumbB = X509CertificateLoader.LoadCertificateFromFile(b).Thumbprint;
        var last = () => KeyLifecycleCommands.RetireCustodian(Site.Load(SiteFolder), thumbB, null, new StringWriter());
        last.Should().Throw<InvalidOperationException>().WithMessage("*only backup*");
    }
}
