using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using IncidentManager.Infrastructure.Security;
using IncidentManager.KeyTool;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// casebook-keytool's signing-key commands (OPERATIONS.md section 2): a key made by new-signing-key is one CaseBook signs
/// with from a file; signing-key-pfx carries the same key, and key id, into the certificate store; signing-public-key gives
/// the public half the retired keys folder reads, from a PEM, a certificate or a site. The PKCS#1 public key Windows
/// PowerShell 5.1 can write from a certificate is read by the retired folder as well.
/// </summary>
[Collection("CertificateStore")]
public sealed class SigningKeyCommandsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-signingkey", Guid.NewGuid().ToString("N"));
    private readonly List<X509Certificate2> _installed = [];

    public SigningKeyCommandsTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
        {
            store.Open(OpenFlags.ReadWrite);
            foreach (var c in _installed)
            {
                store.Remove(c);
                try { if (OperatingSystem.IsWindows() && c.GetRSAPrivateKey() is RSACng cng) cng.Key.Delete(); }
                catch (CryptographicException) { /* gone */ }
                c.Dispose();
            }
        }
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private string At(string name) => Path.Combine(_dir, name);

    private static RsaSealSigner Signer(SealSigningOptions o) => new(Options.Create(o));

    [Fact]
    public void A_new_key_is_one_CaseBook_signs_with_and_its_public_half_is_written_beside_it()
    {
        var keyId = SigningKeyCommands.NewKey(At("seal-signing.pem"), TextWriter.Null);

        using var signer = Signer(new SealSigningOptions { SigningKeyPath = At("seal-signing.pem") });
        signer.KeyId.Should().Be(keyId);
        var signature = signer.Sign("payload");
        signer.Verify("payload", signature, signer.Algorithm, keyId).Should().BeTrue();
        File.ReadAllText(At("seal-signing.public.pem")).Should().StartWith("-----BEGIN PUBLIC KEY-----", "the public half alone");
        SigningKeyCommands.PublicKey(At("seal-signing.public.pem"), null, "CurrentUser", null).KeyId.Should().Be(keyId);
    }

    [Fact]
    public void A_new_key_never_overwrites_a_file()
    {
        File.WriteAllText(At("seal-signing.pem"), "keep me");
        var make = () => SigningKeyCommands.NewKey(At("seal-signing.pem"), TextWriter.Null);
        make.Should().Throw<InvalidOperationException>().WithMessage("*already exists*");
        File.ReadAllText(At("seal-signing.pem")).Should().Be("keep me");
        File.Exists(At("seal-signing.public.pem")).Should().BeFalse();
    }

    [Fact]
    public void The_pfx_carries_the_same_key_into_the_certificate_store()
    {
        var keyId = SigningKeyCommands.NewKey(At("seal-signing.pem"), TextWriter.Null);
        SigningKeyCommands.ToPfx(At("seal-signing.pem"), At("seal.pfx"), "pfx-pw", TextWriter.Null).Should().Be(keyId);

        var cert = X509CertificateLoader.LoadPkcs12FromFile(At("seal.pfx"), "pfx-pw",
            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);
        using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
        {
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
        }
        _installed.Add(cert);

        using var signer = Signer(new SealSigningOptions
        {
            SigningKeyPath = At("absent.pem"),
            SigningKey = new SigningKeyOptions { Source = SigningKeySource.CertificateStore, CertificateThumbprint = cert.Thumbprint, StoreLocation = "CurrentUser" },
        });
        signer.KeyId.Should().Be(keyId, "moving the same key keeps its key id, so earlier seals need nothing");
        signer.Verify("payload", signer.Sign("payload"), signer.Algorithm, keyId).Should().BeTrue();
        SigningKeyCommands.PublicKey(null, cert.Thumbprint, "CurrentUser", null).KeyId.Should().Be(keyId);
    }

    [Fact]
    public void A_pfx_needs_the_private_key()
    {
        SigningKeyCommands.NewKey(At("seal-signing.pem"), TextWriter.Null);
        var wrap = () => SigningKeyCommands.ToPfx(At("seal-signing.public.pem"), At("seal.pfx"), "pfx-pw", TextWriter.Null);
        wrap.Should().Throw<InvalidOperationException>().WithMessage("*public key only*");
        File.Exists(At("seal.pfx")).Should().BeFalse();
    }

    [Fact]
    public void The_public_key_written_for_a_rotation_lets_the_retired_folder_verify_old_seals()
    {
        var oldId = SigningKeyCommands.NewKey(At("old.pem"), TextWriter.Null);
        string oldSignature;
        using (var old = Signer(new SealSigningOptions { SigningKeyPath = At("old.pem"), RetiredPublicKeysPath = At("retired") }))
            oldSignature = old.Sign("payload");

        Directory.CreateDirectory(At("retired"));
        File.WriteAllText(At(Path.Combine("retired", $"{oldId}.pem")), SigningKeyCommands.PublicKey(At("old.pem"), null, "CurrentUser", null).Pem);
        SigningKeyCommands.NewKey(At("new.pem"), TextWriter.Null);

        using var rotated = Signer(new SealSigningOptions { SigningKeyPath = At("new.pem"), RetiredPublicKeysPath = At("retired") });
        rotated.KeyId.Should().NotBe(oldId);
        rotated.Verify("payload", oldSignature, rotated.Algorithm, oldId).Should().BeTrue("a seal is checked with the key it names");
    }

    [Fact]
    public void The_pkcs1_public_key_powershell_writes_from_a_certificate_is_read_by_the_retired_folder()
    {
        // As in OPERATIONS.md: "-----BEGIN RSA PUBLIC KEY-----" around $cert.PublicKey.EncodedKeyValue.RawData.
        using var rsa = RSA.Create(3072);
        using var cert = new CertificateRequest("CN=old signing", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var pkcs1 = "-----BEGIN RSA PUBLIC KEY-----\r\n" +
                    Convert.ToBase64String(cert.PublicKey.EncodedKeyValue.RawData, Base64FormattingOptions.InsertLineBreaks) +
                    "\r\n-----END RSA PUBLIC KEY-----\r\n";
        Directory.CreateDirectory(At("retired"));
        File.WriteAllText(At(Path.Combine("retired", "old.pem")), pkcs1);
        var oldId = RsaSealSigner.KeyIdOf(rsa);
        var oldSignature = Convert.ToBase64String(rsa.SignData("payload"u8.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        SigningKeyCommands.NewKey(At("new.pem"), TextWriter.Null);

        using var rotated = Signer(new SealSigningOptions { SigningKeyPath = At("new.pem"), RetiredPublicKeysPath = At("retired") });
        rotated.VerificationKeys.Select(k => k.KeyId).Should().Contain(oldId);
        rotated.Verify("payload", oldSignature, rotated.Algorithm, oldId).Should().BeTrue();
    }

    [Fact]
    public void A_site_gives_the_key_it_is_configured_with_and_says_where_to_look_for_one_in_CyberArk()
    {
        var keyId = SigningKeyCommands.NewKey(At(Path.Combine("data", "keys", "seal-signing.pem")), TextWriter.Null);
        File.WriteAllText(At("appsettings.Production.json"), System.Text.Json.JsonSerializer.Serialize(new
        {
            Integrity = new { SigningKeyPath = Path.Combine("data", "keys", "seal-signing.pem") },
        }));
        SigningKeyCommands.PublicKey(null, null, "LocalMachine", Site.Load(_dir)).KeyId.Should().Be(keyId, "a relative path resolves against the site, as the app does");

        File.WriteAllText(At("appsettings.Production.json"), System.Text.Json.JsonSerializer.Serialize(new
        {
            Integrity = new { SigningKey = new { Source = "CyberArk", Secret = "@cyberark:Safe=S;Object=O" } },
        }));
        var fromVault = () => SigningKeyCommands.PublicKey(null, null, "LocalMachine", Site.Load(_dir));
        fromVault.Should().Throw<InvalidOperationException>().WithMessage("*CyberArk*compliance bundle*");
    }
}
