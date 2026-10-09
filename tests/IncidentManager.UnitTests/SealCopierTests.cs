using System.Formats.Asn1;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Security;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>F-27: the optional extra seal copies: an email digest and an internal RFC 3161 timestamp.</summary>
public sealed class SealCopierTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-seal-copy-tests", Guid.NewGuid().ToString("N"));

    private static IntegritySeal Seal() => new()
    {
        UpToSequence = 42, ChainHeadHash = new string('a', 64), SealedAtUtc = new DateTimeOffset(2026, 10, 9, 12, 0, 0, TimeSpan.Zero),
        SealedBy = "system", Algorithm = "RSASSA-PSS-SHA256", KeyId = "0123456789abcdef", Signature = "c2ln"
    };

    // ---- Email ----

    private sealed class CapturingEmail : IEmailSender
    {
        public List<(IReadOnlyCollection<string> To, string Subject, string Body)> Sent { get; } = [];
        public Task SendAsync(EmailMessage message, CancellationToken ct = default) => Task.CompletedTask;
        public Task SendAsync(IReadOnlyCollection<string> to, string subject, string body, CancellationToken ct = default)
        {
            Sent.Add((to, subject, body));
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task The_email_digest_carries_the_seal_and_counts_email_off_as_a_failure()
    {
        var email = new CapturingEmail();
        var settings = new TestOptionsMonitor<EmailOptions>(new EmailOptions { Enabled = false });
        var copier = new EmailSealCopier(email, settings,
            Options.Create(new SealCopyOptions { EmailTo = "seals@contoso.com; audit@contoso.com" }));

        var off = () => copier.CopyAsync(Seal());
        await off.Should().ThrowAsync<InvalidOperationException>().WithMessage("*Email is turned off*");

        settings.CurrentValue = new EmailOptions { Enabled = true };
        await copier.CopyAsync(Seal());

        var sent = email.Sent.Should().ContainSingle().Subject;
        sent.To.Should().Equal("seals@contoso.com", "audit@contoso.com");
        sent.Subject.Should().Be("CaseBook integrity seal #42");
        sent.Body.Should().Contain(new string('a', 64)).And.Contain("0123456789abcdef").And.Contain("2026-10-09T12:00:00");
    }

    // ---- Timestamp authority ----

    [Theory]
    [InlineData("http://10.20.30.40/tsa", true)]
    [InlineData("https://172.16.0.5/tsa", true)]
    [InlineData("http://192.168.1.10:8080/", true)]
    [InlineData("http://127.0.0.1/tsa", true)]
    [InlineData("http://localhost/tsa", true)]
    [InlineData("http://8.8.8.8/tsa", false)]
    [InlineData("http://172.32.0.1/tsa", false)]
    [InlineData("ftp://10.0.0.1/tsa", false)]
    [InlineData("not a url", false)]
    public void Only_internal_timestamp_authorities_are_accepted(string url, bool accepted)
    {
        var act = () => TimestampSealCopier.RequireInternal(url);

        if (accepted) act.Should().NotThrow();
        else act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public async Task A_seal_is_timestamped_and_the_token_saved_beside_its_copy()
    {
        using var tsa = new FakeTimestampAuthority();
        using var copier = new TimestampSealCopier(
            Options.Create(new SealCopyOptions { TimestampAuthorityUrl = "http://127.0.0.1/tsa" }),
            Options.Create(new SealSigningOptions { ExportPath = _dir }), tsa);

        await copier.CopyAsync(Seal());

        var file = Directory.GetFiles(_dir, "*.tsr").Should().ContainSingle().Subject;
        Path.GetFileName(file).Should().Be("seal-000000042-20261009T120000Z.tsr");
        Rfc3161TimestampToken.TryDecode(File.ReadAllBytes(file), out var token, out _).Should().BeTrue();
        token!.VerifySignatureForData(System.Text.Encoding.UTF8.GetBytes(Seal().BuildCanonicalContent()), out _).Should().BeTrue();
    }

    [Fact]
    public async Task A_timestamp_authority_that_refuses_is_a_failed_copy()
    {
        using var copier = new TimestampSealCopier(
            Options.Create(new SealCopyOptions { TimestampAuthorityUrl = "http://127.0.0.1/tsa" }),
            Options.Create(new SealSigningOptions { ExportPath = _dir }), new Refusing());

        var act = () => copier.CopyAsync(Seal());

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*answered 503*");
        Directory.Exists(_dir).Should().BeFalse("nothing is saved without a token");
    }

    private sealed class Refusing : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
    }

    /// <summary>A minimal RFC 3161 authority: signs a TSTInfo for the request's hash and nonce with a timestamping certificate.</summary>
    private sealed class FakeTimestampAuthority : HttpMessageHandler
    {
        private readonly X509Certificate2 _cert;

        public FakeTimestampAuthority()
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest("CN=Test TSA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.8")], critical: true));
            _cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = await request.Content!.ReadAsByteArrayAsync(ct);
            Rfc3161TimestampRequest.TryDecode(body, out var tsq, out _).Should().BeTrue();
            var info = new Rfc3161TimestampTokenInfo(new Oid("1.2.3.4"), tsq!.HashAlgorithmId, tsq.GetMessageHash(),
                new BigInteger(7).ToByteArray(), DateTimeOffset.UtcNow, nonce: tsq.GetNonce());

            var cms = new SignedCms(new ContentInfo(new Oid("1.2.840.113549.1.9.16.1.4"), info.Encode()));
            var signer = new CmsSigner(_cert) { IncludeOption = X509IncludeOption.EndCertOnly, DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1") };
            // id-aa-signingCertificateV2: { certs: [ { certHash: SHA-256(cert) } ] }
            var w = new AsnWriter(AsnEncodingRules.DER);
            using (w.PushSequence()) using (w.PushSequence()) using (w.PushSequence()) w.WriteOctetString(SHA256.HashData(_cert.RawData));
            signer.SignedAttributes.Add(new AsnEncodedData("1.2.840.113549.1.9.16.2.47", w.Encode()));
            cms.ComputeSignature(signer);

            // TimeStampResp: { status: { granted (0) }, timeStampToken }
            var resp = new AsnWriter(AsnEncodingRules.DER);
            using (resp.PushSequence())
            {
                using (resp.PushSequence()) resp.WriteInteger(0);
                resp.WriteEncodedValue(cms.Encode());
            }
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(resp.Encode()) };
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _cert.Dispose();
            base.Dispose(disposing);
        }
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }
}
