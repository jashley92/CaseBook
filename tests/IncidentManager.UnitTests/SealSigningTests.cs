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
