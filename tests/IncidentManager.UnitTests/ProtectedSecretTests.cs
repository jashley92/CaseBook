using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Secrets;
using IncidentManager.Infrastructure.Security;
using Microsoft.Extensions.Logging;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// CAP-05 (ADR 0018): a <c>@protected:</c> value opens only with the private key of the certificate it names, and fails
/// closed otherwise (another certificate, a changed byte, a certificate that isn't there, an unknown version); the
/// provider opens it in front of whichever provider is behind it and hands every other value on unchanged.
/// </summary>
public sealed class ProtectedSecretTests : IDisposable
{
    private readonly (X509Certificate2 Cert, byte[] Pfx) _a = Make("CN=CaseBook protected secret test");
    private readonly (X509Certificate2 Cert, byte[] Pfx) _b = Make("CN=CaseBook another certificate");
    private X509Certificate2 Cert => _a.Cert;
    private X509Certificate2 Other => _b.Cert;

    // S2068: no secret is written in the source; each test makes its own.
    private static string NewSecret() => "s-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12));

    private static (X509Certificate2, byte[]) Make(string subject)
    {
        using var rsa = RSA.Create(2048);
        using var made = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var pfx = made.Export(X509ContentType.Pfx, "");
        return (X509CertificateLoader.LoadPkcs12(pfx, "", X509KeyStorageFlags.EphemeralKeySet), pfx);
    }

    private static X509Certificate2 Fresh(byte[] pfx) => X509CertificateLoader.LoadPkcs12(pfx, "", X509KeyStorageFlags.EphemeralKeySet);

    // The lookup the provider is given, for the first certificate's thumbprint only: a fresh copy of the certificate given
    // each time (the caller disposes what it's handed).
    private Func<string, X509Certificate2> Lookup(X509Certificate2 cert) => thumbprint =>
        string.Equals(thumbprint, CertificateLookup.Normalize(Cert.Thumbprint), StringComparison.Ordinal)
            ? Fresh(ReferenceEquals(cert, Cert) ? _a.Pfx : _b.Pfx)
            : throw new InvalidOperationException($"no certificate {thumbprint} here");

    public void Dispose()
    {
        _a.Cert.Dispose();
        _b.Cert.Dispose();
    }

    [Fact]
    public void A_value_round_trips_and_names_its_certificate()
    {
        var secret = NewSecret() + " with spaces, ünïcode and a : colon";
        var value = ProtectedSecret.Protect(secret, Cert);

        value.Should().StartWith("@protected:v1:" + CertificateLookup.Normalize(Cert.Thumbprint) + ":");
        value.Should().NotContain(secret);
        ProtectedSecret.ThumbprintOf(value).Should().Be(CertificateLookup.Normalize(Cert.Thumbprint));
        ProtectedSecret.TryOpen(value, Lookup(Cert), out var opened, out var reason).Should().BeTrue(reason);
        opened.Should().Be(secret);
        ProtectedSecret.Protect(secret, Cert).Should().NotBe(value, "a new random key and nonce every time");
    }

    [Fact]
    public void Only_the_public_key_is_needed_to_protect()
    {
        using var publicOnly = X509CertificateLoader.LoadCertificate(Cert.Export(X509ContentType.Cert));
        publicOnly.HasPrivateKey.Should().BeFalse();
        var secret = NewSecret();
        ProtectedSecret.TryOpen(ProtectedSecret.Protect(secret, publicOnly), Lookup(Cert), out var opened, out _).Should().BeTrue();
        opened.Should().Be(secret);
    }

    [Fact]
    public void Another_certificates_key_doesnt_open_it()
    {
        var value = ProtectedSecret.Protect(NewSecret(), Cert);
        ProtectedSecret.TryOpen(value, Lookup(Other), out var opened, out var reason).Should().BeFalse();
        opened.Should().BeNull();
        reason.Should().Contain("doesn't open");
    }

    [Theory]
    [InlineData(0)]     // the wrapped key
    [InlineData(-1)]    // the ciphertext's last byte
    [InlineData(-20)]   // the tag
    public void A_changed_byte_fails_closed(int at)
    {
        var secret = NewSecret();
        var value = ProtectedSecret.Protect(secret, Cert);
        var prefix = value[..(value.LastIndexOf(':') + 1)];
        var blob = Convert.FromBase64String(value[prefix.Length..]);
        blob[at < 0 ? blob.Length + at : at] ^= 0x01;
        ProtectedSecret.TryOpen(prefix + Convert.ToBase64String(blob), Lookup(Cert), out var opened, out var reason).Should().BeFalse();
        opened.Should().BeNull();
        reason.Should().NotContain(secret);
    }

    [Fact]
    public void A_value_moved_to_another_thumbprint_fails_closed(/* the thumbprint is authenticated data */)
    {
        var value = ProtectedSecret.Protect(NewSecret(), Cert);
        var moved = value.Replace(CertificateLookup.Normalize(Cert.Thumbprint), CertificateLookup.Normalize(Other.Thumbprint), StringComparison.Ordinal);
        // The lookup hands the original certificate for any thumbprint: only the associated data can tell.
        ProtectedSecret.TryOpen(moved, _ => Fresh(_a.Pfx), out _, out _).Should().BeFalse();
    }

    [Fact]
    public void An_unknown_thumbprint_fails_closed_with_the_lookups_reason()
    {
        var value = ProtectedSecret.Protect(NewSecret(), Other);
        ProtectedSecret.TryOpen(value, Lookup(Cert), out var opened, out var reason).Should().BeFalse();
        opened.Should().BeNull();
        reason.Should().Contain("no certificate");
    }

    [Theory]
    [InlineData("@protected:")]
    [InlineData("@protected:v1:ABC:AAAA")]                                            // a short thumbprint
    [InlineData("@protected:v2:0123456789ABCDEF0123456789ABCDEF01234567:AAAA")]       // an unknown version
    [InlineData("@protected:v1:0123456789ABCDEF0123456789ABCDEF01234567:not base64!")]
    [InlineData("@protected:v1:0123456789ABCDEF0123456789ABCDEF01234567:AAAA")]       // too short to be one
    public void A_malformed_value_fails_closed(string value) =>
        ProtectedSecret.TryOpen(value, Lookup(Cert), out _, out _).Should().BeFalse();

    [Theory]
    [InlineData("@protected:v1:x:y", true)]
    [InlineData("  @Protected:v1:x:y", true)]   // REV-10: as a reference is read
    [InlineData("@cyberark:Safe=S;Object=O", false)]
    [InlineData("plain", false)]
    [InlineData(null, false)]
    public void IsProtected_tells_a_protected_value(string? value, bool expected) =>
        ProtectedSecret.IsProtected(value).Should().Be(expected);

    // --- The provider in front of passthrough or CyberArk ----------------------------------------

    private sealed class RecordingInner : ISecretProvider
    {
        public readonly List<string?> Asked = [];
        public ValueTask<string?> ResolveAsync(string? configuredValue, CancellationToken ct = default)
        {
            Asked.Add(configuredValue);
            return ValueTask.FromResult(configuredValue?.StartsWith("@cyberark:", StringComparison.Ordinal) == true ? "from-vault" : configuredValue);
        }
    }

    private sealed class CountingLogger : ILogger<ProtectedSecretProvider>
    {
        public readonly List<string> Warnings = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel >= LogLevel.Warning) Warnings.Add(formatter(state, exception));
        }
    }

    [Fact]
    public async Task The_provider_opens_protected_values_and_hands_the_rest_on()
    {
        var inner = new RecordingInner();
        var provider = new ProtectedSecretProvider(inner, new CountingLogger(), Lookup(Cert));
        var secret = NewSecret();

        (await provider.ResolveAsync(ProtectedSecret.Protect(secret, Cert))).Should().Be(secret);
        (await provider.ResolveAsync("literal")).Should().Be("literal");
        (await provider.ResolveAsync("@cyberark:Safe=S;Object=O")).Should().Be("from-vault");
        (await provider.ResolveAsync(null)).Should().BeNull();
        inner.Asked.Should().Equal("literal", "@cyberark:Safe=S;Object=O", null);
    }

    [Fact]
    public async Task One_that_wont_open_is_null_and_logged_once_without_its_content()
    {
        var log = new CountingLogger();
        var provider = new ProtectedSecretProvider(new RecordingInner(), log, Lookup(Cert));
        var secret = NewSecret();
        var value = ProtectedSecret.Protect(secret, Other);   // the lookup has no such certificate

        (await provider.ResolveAsync(value)).Should().BeNull("fail closed: never the value's text");
        (await provider.ResolveAsync(value)).Should().BeNull();
        log.Warnings.Should().ContainSingle().Which.Should().Contain(CertificateLookup.Normalize(Other.Thumbprint))
            .And.NotContain(secret).And.NotContain(value);
    }
}
