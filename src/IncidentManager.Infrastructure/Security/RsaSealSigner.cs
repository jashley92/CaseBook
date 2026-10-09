using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// Signs integrity seals with RSA (RSASSA-PSS over SHA-256, MGF1-SHA256, 32-byte salt). The key comes from the configured
/// source (F-23): a PEM file (the default), a certificate in the Windows certificate store, or a PEM held in CyberArk.
/// Only in Development (<see cref="SealSigningOptions.AllowKeyGeneration"/>, file source) is a missing key generated and
/// persisted; anywhere else a missing or unresolvable key stops startup, because a key the app made for itself on the
/// server can't vouch for anything — it must be provisioned out of band.
/// </summary>
public sealed class RsaSealSigner : ISealSigner, IDisposable
{
    private const int KeySizeBits = 3072;
    private const int MinKeySizeBits = 2048;
    private readonly RSA _rsa;
    private readonly X509Certificate2? _certificate;
    private readonly Dictionary<string, RSA> _retired = new(StringComparer.OrdinalIgnoreCase);

    public string Algorithm => SealAlgorithms.Pss;
    public string KeyId { get; }

    /// <summary>Where the key came from, for the Integrity page and Diagnostics (no secrets).</summary>
    public string KeySource { get; }

    /// <summary>The public key in PEM (SubjectPublicKeyInfo) form for independent, offline verification.</summary>
    public string PublicKeyPem => _rsa.ExportSubjectPublicKeyInfoPem();

    public RsaSealSigner(IOptions<SealSigningOptions> options, ISecretProvider? secrets = null)
    {
        var o = options.Value;
        (_rsa, _certificate, KeySource) = o.SigningKey.Source switch
        {
            SigningKeySource.CertificateStore => FromCertificate(o.SigningKey),
            SigningKeySource.CyberArk => FromCyberArk(o.SigningKey, secrets),
            _ => (FromFile(o.SigningKeyPath, o.AllowKeyGeneration), null, $"File ({Path.GetFullPath(o.SigningKeyPath)})")
        };
        if (_rsa.KeySize < MinKeySizeBits)
        {
            Dispose();
            throw new InvalidOperationException($"The seal signing key is {_rsa.KeySize}-bit; use RSA {MinKeySizeBits} bits or more.");
        }

        // Thumbprint the public key so a seal can record which key signed it.
        KeyId = KeyIdOf(_rsa);
        LoadRetiredKeys(o);
        VerificationKeys = [new SealPublicKey(KeyId, PublicKeyPem, true),
            .. _retired.OrderBy(k => k.Key, StringComparer.Ordinal)
                .Select(k => new SealPublicKey(k.Key, k.Value.ExportSubjectPublicKeyInfoPem(), false))];
    }

    private static RSA FromFile(string path, bool allowGeneration)
    {
        var rsa = RSA.Create(KeySizeBits);
        if (File.Exists(path))
        {
            rsa.ImportFromPem(File.ReadAllText(path));
            return rsa;
        }

        if (!allowGeneration)
        {
            rsa.Dispose();
            throw new InvalidOperationException(
                $"The seal-signing key '{Path.GetFullPath(path)}' (Integrity:SigningKeyPath) doesn't exist. " +
                "Outside Development the app won't generate one: provision the key out of band (see OPERATIONS.md §2), then restart.");
        }

        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var pem = rsa.ExportRSAPrivateKeyPem();
        File.WriteAllText(path, pem);
        TryRestrictToOwner(path);
        return rsa;
    }

    // F-23: Windows signs with the certificate's private key; a key marked non-exportable is used, never copied out.
    private static (RSA, X509Certificate2?, string) FromCertificate(SigningKeyOptions k)
    {
        var thumbprint = new string(k.CertificateThumbprint.Where(char.IsAsciiHexDigit).ToArray()).ToUpperInvariant();
        if (thumbprint.Length == 0)
            throw new InvalidOperationException("Integrity:SigningKey:Source is CertificateStore but Integrity:SigningKey:CertificateThumbprint is empty.");
        if (!Enum.TryParse<StoreLocation>(k.StoreLocation, ignoreCase: true, out var location))
            throw new InvalidOperationException($"Integrity:SigningKey:StoreLocation '{k.StoreLocation}' isn't LocalMachine or CurrentUser.");

        using var store = new X509Store(StoreName.My, location);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        var cert = found.Count > 0 ? found[0] : null;
        foreach (var other in found.Skip(1)) other.Dispose();
        if (cert is null)
            throw new InvalidOperationException($"No certificate with thumbprint {thumbprint} in {location}\\My (Integrity:SigningKey:CertificateThumbprint).");
        if (!cert.HasPrivateKey)
        {
            cert.Dispose();
            throw new InvalidOperationException($"The certificate {thumbprint} in {location}\\My has no private key, or the app account can't read it. Grant it read on the private key.");
        }
        var rsa = cert.GetRSAPrivateKey();
        if (rsa is null)
        {
            cert.Dispose();
            throw new InvalidOperationException($"The certificate {thumbprint} isn't an RSA certificate; seals need an RSA key.");
        }
        return (rsa, cert, $"Certificate store ({location}\\My, thumbprint {thumbprint})");
    }

    // F-23: the PEM comes from CyberArk at startup and stays in memory; it's never written to disk.
    private static (RSA, X509Certificate2?, string) FromCyberArk(SigningKeyOptions k, ISecretProvider? secrets)
    {
        if (string.IsNullOrWhiteSpace(k.Secret))
            throw new InvalidOperationException("Integrity:SigningKey:Source is CyberArk but Integrity:SigningKey:Secret is empty.");
        if (!k.Secret.TrimStart().StartsWith("@cyberark:", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Integrity:SigningKey:Secret must be an @cyberark:Safe=…;Object=… reference; the key itself never goes in configuration.");
        if (secrets is null)
            throw new InvalidOperationException("Integrity:SigningKey:Source is CyberArk but no secret provider is available.");

        var pem = secrets.ResolveAsync(k.Secret).AsTask().GetAwaiter().GetResult();
        if (string.IsNullOrWhiteSpace(pem))
            throw new InvalidOperationException("The seal signing key couldn't be fetched from CyberArk (Integrity:SigningKey:Secret). " +
                "Check Secrets:CyberArk is enabled and Administration → Diagnostics → Secret resolution.");
        var rsa = RSA.Create();
        try { rsa.ImportFromPem(pem); }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            rsa.Dispose();
            throw new InvalidOperationException("The secret CyberArk returned for Integrity:SigningKey:Secret isn't an RSA private key in PEM form.", ex);
        }
        return (rsa, null, "CyberArk");
    }

    public IReadOnlyList<SealPublicKey> VerificationKeys { get; }

    /// <summary>A key's id: the first 16 hex characters of the SHA-256 of its SubjectPublicKeyInfo.</summary>
    public static string KeyIdOf(RSA rsa) =>
        Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()))[..16].ToLowerInvariant();

    /// <summary>The folder retired public keys are read from: the configured one, or <c>retired</c> beside the key.</summary>
    public static string RetiredFolder(SealSigningOptions o) =>
        !string.IsNullOrWhiteSpace(o.RetiredPublicKeysPath) ? o.RetiredPublicKeysPath
        : Path.Combine(Path.GetDirectoryName(Path.GetFullPath(o.SigningKeyPath)) ?? ".", "retired");

    // F-24: each *.pem in the folder is a public key (or a private key, of which only the public half is kept). A file
    // that isn't a readable RSA key stops startup, so a typo can't quietly leave seals unverifiable.
    private void LoadRetiredKeys(SealSigningOptions o)
    {
        var folder = RetiredFolder(o);
        if (!Directory.Exists(folder)) return;
        foreach (var file in Directory.EnumerateFiles(folder, "*.pem").Order(StringComparer.Ordinal))
        {
            var rsa = RSA.Create();
            try
            {
                rsa.ImportFromPem(File.ReadAllText(file));
                var pub = RSA.Create();
                pub.ImportSubjectPublicKeyInfo(rsa.ExportSubjectPublicKeyInfo(), out _);
                var id = KeyIdOf(pub);
                if (id == KeyId || !_retired.TryAdd(id, pub)) pub.Dispose();   // the current key, or a duplicate
            }
            catch (Exception ex) when (ex is ArgumentException or CryptographicException)
            {
                throw new InvalidOperationException(
                    $"'{file}' in the retired seal keys folder isn't a readable RSA key in PEM form. Fix or remove it, then restart.", ex);
            }
            finally { rsa.Dispose(); }
        }
    }

    /// <summary>Best-effort tightening of the key file's permissions to the current user only.</summary>
    private static void TryRestrictToOwner(string path)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var info = new FileInfo(path);
                var security = info.GetAccessControl();
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                var owner = System.Security.Principal.WindowsIdentity.GetCurrent().User;
                if (owner is not null)
                {
                    security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                        owner,
                        System.Security.AccessControl.FileSystemRights.FullControl,
                        System.Security.AccessControl.AccessControlType.Allow));
                }
                info.SetAccessControl(security);
            }
            else
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch
        {
            // Non-fatal: the key still works; the directory itself lives under restricted App_Data.
        }
    }

    public string Sign(string content)
    {
        var sig = _rsa.SignData(Encoding.UTF8.GetBytes(content), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return Convert.ToBase64String(sig);
    }

    public bool Verify(string content, string signatureBase64, string? algorithm = null, string? keyId = null)
    {
        if (SealAlgorithms.PaddingFor(algorithm) is not { } padding) return false;
        var key = string.IsNullOrEmpty(keyId) || string.Equals(keyId, KeyId, StringComparison.OrdinalIgnoreCase) ? _rsa
            : _retired.GetValueOrDefault(keyId);
        if (key is null) return false;
        byte[] sig;
        try { sig = Convert.FromBase64String(signatureBase64); }
        catch (FormatException) { return false; }

        return key.VerifyData(Encoding.UTF8.GetBytes(content), sig, HashAlgorithmName.SHA256, padding);
    }

    public void Dispose()
    {
        _rsa.Dispose();
        _certificate?.Dispose();
        foreach (var k in _retired.Values) k.Dispose();
    }
}
