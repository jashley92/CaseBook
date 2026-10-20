using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using IncidentManager.Web.Ops;
using IncidentManager.Web.Services;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace IncidentManager.IntegrationTests;

public class CertificateExpiryTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 20, 12, 0, 0, TimeSpan.Zero);

    private static X509Certificate2 Cert(string name, DateTimeOffset notAfter)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(notAfter.AddYears(-1), notAfter);
    }

    private static IConfiguration Config(Dictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    [Fact]
    public void Only_the_certificates_in_use_are_read_and_one_used_twice_is_listed_once()
    {
        var config = Config(new()
        {
            ["Integrity:SigningKey:Source"] = "CertificateStore",
            ["Integrity:SigningKey:CertificateThumbprint"] = "aa bb cc",
            ["Integrity:ChainKey:Enabled"] = "true",
            ["Integrity:ChainKey:Source"] = "Certificate",
            ["Integrity:ChainKey:CertificateThumbprint"] = "AABBCC",
            ["Storage:Encryption:Enabled"] = "false",
            ["Storage:Encryption:CertificateThumbprint"] = "DDEEFF",   // off, so not watched
            ["Email:SmtpPassword"] = "plain text",                     // not @protected:
        });
        using var cert = Cert("signing", Now.AddYears(2));
        var items = CertificateExpiry.Read(CertificateExpiry.Uses(config), (_, _) => new X509Certificate2(cert), null, _ => null);

        items.Should().ContainSingle();
        items[0].Thumbprint.Should().Be("AABBCC");
        items[0].Purpose.Should().Be("Seal signing key, Audit chain key");
    }

    [Fact]
    public void An_expiring_expired_or_missing_certificate_is_flagged_and_a_healthy_set_is_one_line()
    {
        var soon = new CertificateExpiryItem("Evidence key server lock", "AA", "CN=lock", Now.AddDays(30), "Storage:Encryption:CertificateThumbprint");
        var gone = new CertificateExpiryItem("Seal signing key", "BB", "CN=sign", Now.AddDays(-1), "Integrity:SigningKey:CertificateThumbprint");
        var missing = new CertificateExpiryItem("Syslog client certificate", "CC", null, null, "Siem:Syslog:ClientCertificateThumbprint");
        var fine = new CertificateExpiryItem("TLS, probably (its name matches casebook.contoso.com)", "DD", "CN=casebook", Now.AddDays(200), "IIS binding");

        var flagged = AdminHealth.CertificateChecks([soon, gone, missing, fine], Now).ToList();
        flagged.Should().HaveCount(3).And.OnlyContain(c => !c.Ok);
        flagged.Single(c => c.Label.Contains("server lock")).Detail.Should().Contain("expires").And.Contain("Storage:Encryption:CertificateThumbprint");
        flagged.Single(c => c.Label.Contains("signing")).Detail.Should().Contain("expired");

        var ok = AdminHealth.CertificateChecks([fine], Now).Single();
        ok.Ok.Should().BeTrue();
        ok.Detail.Should().Contain("1 certificate");
    }
}
