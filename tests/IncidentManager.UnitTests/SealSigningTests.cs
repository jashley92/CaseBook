using FluentAssertions;
using IncidentManager.Infrastructure.Security;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.UnitTests;

public class SealSigningTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-seal-key-tests", Guid.NewGuid().ToString("N"));

    private RsaSealSigner NewSigner() =>
        new(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(_dir, "k.pem"), AllowKeyGeneration = true }));

    [Fact]
    public void Sign_then_verify_roundtrips()
    {
        using var signer = NewSigner();

        var sig = signer.Sign("payload");

        signer.Verify("payload", sig).Should().BeTrue();
        signer.KeyId.Should().NotBeNullOrEmpty();
        signer.Algorithm.Should().Be("RSASSA-PSS-SHA256");
    }

    // Seals made before v1.4.0 were signed with PKCS#1 v1.5 and record that algorithm; they still verify, each by
    // its own algorithm, so an upgraded site's history doesn't read as tampered.
    [Fact]
    public void A_seal_verifies_by_the_algorithm_it_records()
    {
        using var signer = NewSigner();
        using var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(Path.Combine(_dir, "k.pem")));
        var legacy = Convert.ToBase64String(rsa.SignData("payload"u8.ToArray(),
            System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1));
        var current = signer.Sign("payload");

        signer.Verify("payload", legacy, "RSASSA-PKCS1-v1_5-SHA256").Should().BeTrue();
        signer.Verify("payload", legacy, "RSASSA-PSS-SHA256").Should().BeFalse("a padding the seal didn't use");
        signer.Verify("payload", current, "RSASSA-PSS-SHA256").Should().BeTrue();
        signer.Verify("payload", current, "RSASSA-PKCS1-v1_5-SHA256").Should().BeFalse();
        signer.Verify("payload", current, "SHA1withRSA").Should().BeFalse("an unknown algorithm never verifies");
        signer.Verify("payload-tampered", legacy, "RSASSA-PKCS1-v1_5-SHA256").Should().BeFalse();
    }

    // F-24: after a key change, seals signed by the old key verify against its public key kept in the retired folder.
    [Fact]
    public void After_a_key_change_old_seals_verify_by_the_retired_key_they_name()
    {
        string oldId, oldSig;
        using (var old = NewSigner())
        {
            oldId = old.KeyId;
            oldSig = old.Sign("payload");
            Directory.CreateDirectory(Path.Combine(_dir, "retired"));
            File.WriteAllText(Path.Combine(_dir, "retired", "old.pem"), old.PublicKeyPem);
        }
        File.Delete(Path.Combine(_dir, "k.pem"));   // rotate: a new signing key in the same place

        using var current = NewSigner();
        current.KeyId.Should().NotBe(oldId);
        current.Verify("payload", oldSig, "RSASSA-PSS-SHA256", oldId).Should().BeTrue();
        current.Verify("payload", oldSig, "RSASSA-PSS-SHA256", current.KeyId).Should().BeFalse("the current key didn't sign it");
        current.Verify("payload", oldSig, "RSASSA-PSS-SHA256", "0000000000000000").Should().BeFalse("an unknown key never verifies");
        current.Verify("payload", current.Sign("payload"), "RSASSA-PSS-SHA256", current.KeyId).Should().BeTrue();
        current.VerificationKeys.Select(k => (k.KeyId, k.Current)).Should().Equal((current.KeyId, true), (oldId, false));
    }

    // ---- F-23: where the signing key comes from ----

    private sealed class FakeSecrets(Dictionary<string, string?> values) : IncidentManager.Application.Abstractions.ISecretProvider
    {
        public ValueTask<string?> ResolveAsync(string? configuredValue, CancellationToken ct = default) =>
            ValueTask.FromResult(configuredValue is not null && values.TryGetValue(configuredValue, out var v) ? v : null);
    }

    private RsaSealSigner Signer(SigningKeyOptions key, IncidentManager.Application.Abstractions.ISecretProvider? secrets = null) =>
        new(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(_dir, "k.pem"), SigningKey = key }), secrets);

    [Fact]
    public void The_key_can_come_from_cyberark_and_stays_in_memory()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(3072);
        const string reference = "@cyberark:Safe=Seals;Object=CaseBook-Seal-Key";
        var secrets = new FakeSecrets(new() { [reference] = rsa.ExportRSAPrivateKeyPem() });

        using var signer = Signer(new SigningKeyOptions { Source = SigningKeySource.CyberArk, Secret = reference }, secrets);

        signer.KeySource.Should().Be("CyberArk");
        signer.KeyId.Should().Be(RsaSealSigner.KeyIdOf(rsa));
        signer.Verify("payload", signer.Sign("payload")).Should().BeTrue();
        File.Exists(Path.Combine(_dir, "k.pem")).Should().BeFalse("a CyberArk key is never written to disk");
    }

    [Fact]
    public void A_cyberark_key_that_cant_be_fetched_or_isnt_a_reference_stops_startup()
    {
        var empty = new FakeSecrets(new());

        var unresolved = () => Signer(new SigningKeyOptions { Source = SigningKeySource.CyberArk, Secret = "@cyberark:Safe=X;Object=Y" }, empty);
        var literal = () => Signer(new SigningKeyOptions { Source = SigningKeySource.CyberArk, Secret = "-----BEGIN RSA PRIVATE KEY-----" }, empty);
        var notAKey = () => Signer(new SigningKeyOptions { Source = SigningKeySource.CyberArk, Secret = "@cyberark:Safe=X;Object=Z" },
            new FakeSecrets(new() { ["@cyberark:Safe=X;Object=Z"] = "hunter2" }));

        unresolved.Should().Throw<InvalidOperationException>().WithMessage("*couldn't be fetched from CyberArk*");
        literal.Should().Throw<InvalidOperationException>().WithMessage("*must be an @cyberark:*");
        notAKey.Should().Throw<InvalidOperationException>().WithMessage("*isn't an RSA private key*");
    }

    [Fact]
    public void The_key_can_come_from_the_certificate_store()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(3072);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=CaseBook seal test",
            rsa, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pss);
        using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        // Round-trip through PFX so the private key is persisted with the certificate in the store.
        using var cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12(ephemeral.Export(
                System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "t"), "t",
            System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.PersistKeySet
            | System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.UserKeySet);
        using var store = new System.Security.Cryptography.X509Certificates.X509Store(
            System.Security.Cryptography.X509Certificates.StoreName.My, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
        store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);
        store.Add(cert);
        try
        {
            using var signer = Signer(new SigningKeyOptions
            {
                Source = SigningKeySource.CertificateStore, StoreLocation = "CurrentUser",
                CertificateThumbprint = string.Join(' ', cert.Thumbprint.Chunk(2).Select(c => new string(c)))   // spaces as copied from MMC
            });

            signer.KeySource.Should().Contain("Certificate store").And.Contain(cert.Thumbprint);
            signer.KeyId.Should().Be(RsaSealSigner.KeyIdOf(rsa));
            signer.Verify("payload", signer.Sign("payload")).Should().BeTrue();
        }
        finally
        {
            store.Remove(cert);
            // On Windows the imported private key persists in the user's key store; delete it too.
            try { if (OperatingSystem.IsWindows() && System.Security.Cryptography.X509Certificates.RSACertificateExtensions.GetRSAPrivateKey(cert) is System.Security.Cryptography.RSACng cng) cng.Key.Delete(); }
            catch (System.Security.Cryptography.CryptographicException) { /* already gone */ }
        }
    }

    [Fact]
    public void A_certificate_that_isnt_there_stops_startup()
    {
        var act = () => Signer(new SigningKeyOptions
        {
            Source = SigningKeySource.CertificateStore, StoreLocation = "CurrentUser", CertificateThumbprint = new string('0', 40)
        });

        act.Should().Throw<InvalidOperationException>().WithMessage("*No certificate with thumbprint*");
    }

    [Fact]
    public void A_retired_keys_folder_entry_that_isnt_a_key_stops_startup()
    {
        Directory.CreateDirectory(Path.Combine(_dir, "retired"));
        File.WriteAllText(Path.Combine(_dir, "retired", "typo.pem"), "not a key");

        var act = () => NewSigner();

        act.Should().Throw<InvalidOperationException>().WithMessage("*typo.pem*retired seal keys folder*");
    }

    [Fact]
    public void Verify_fails_when_the_content_is_altered()
    {
        using var signer = NewSigner();
        var sig = signer.Sign("payload");

        signer.Verify("payload-tampered", sig).Should().BeFalse();
    }

    [Fact]
    public void Verify_fails_on_a_garbage_signature()
    {
        using var signer = NewSigner();

        signer.Verify("payload", "not-valid-base64!!").Should().BeFalse();
    }

    [Fact]
    public void The_persisted_key_is_reused_across_instances()
    {
        string sig, keyId;
        using (var first = NewSigner())
        {
            sig = first.Sign("payload");
            keyId = first.KeyId;
        }

        // A new signer loads the same key file, so it keeps the same identity and verifies prior signatures.
        using var second = NewSigner();
        second.KeyId.Should().Be(keyId);
        second.Verify("payload", sig).Should().BeTrue();
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }
}
