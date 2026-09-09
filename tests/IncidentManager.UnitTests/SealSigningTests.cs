using FluentAssertions;
using IncidentManager.Infrastructure.Security;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.UnitTests;

public class SealSigningTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-seal-key-tests", Guid.NewGuid().ToString("N"));

    private RsaSealSigner NewSigner() =>
        new(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(_dir, "k.pem") }));

    [Fact]
    public void Sign_then_verify_roundtrips()
    {
        using var signer = NewSigner();

        var sig = signer.Sign("payload");

        signer.Verify("payload", sig).Should().BeTrue();
        signer.KeyId.Should().NotBeNullOrEmpty();
        signer.Algorithm.Should().Be("RSASSA-PKCS1-v1_5-SHA256");
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
