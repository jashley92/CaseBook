using System.Security.Cryptography;
using System.Text;
using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// Signs integrity seals with RSA (RSASSA-PSS over SHA-256, MGF1-SHA256, 32-byte salt). The private key is loaded from
/// the configured PEM file. Only in Development (<see cref="SealSigningOptions.AllowKeyGeneration"/>) is a
/// missing key generated and persisted there; anywhere else a missing key is refused, because a key the app
/// made for itself on the server can't vouch for anything — it must be provisioned out of band.
/// </summary>
public sealed class RsaSealSigner : ISealSigner, IDisposable
{
    private const int KeySizeBits = 3072;
    private readonly RSA _rsa;
    private readonly Dictionary<string, RSA> _retired = new(StringComparer.OrdinalIgnoreCase);

    public string Algorithm => SealAlgorithms.Pss;
    public string KeyId { get; }

    /// <summary>The public key in PEM (SubjectPublicKeyInfo) form for independent, offline verification.</summary>
    public string PublicKeyPem => _rsa.ExportSubjectPublicKeyInfoPem();

    public RsaSealSigner(IOptions<SealSigningOptions> options)
    {
        var path = options.Value.SigningKeyPath;
        _rsa = RSA.Create(KeySizeBits);
        LoadOrCreateKey(path, options.Value.AllowKeyGeneration);

        // Thumbprint the public key so a seal can record which key signed it.
        KeyId = KeyIdOf(_rsa);
        LoadRetiredKeys(options.Value);
        VerificationKeys = [new SealPublicKey(KeyId, PublicKeyPem, true),
            .. _retired.OrderBy(k => k.Key, StringComparer.Ordinal)
                .Select(k => new SealPublicKey(k.Key, k.Value.ExportSubjectPublicKeyInfoPem(), false))];
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

    private void LoadOrCreateKey(string path, bool allowGeneration)
    {
        if (File.Exists(path))
        {
            _rsa.ImportFromPem(File.ReadAllText(path));
            return;
        }

        if (!allowGeneration)
        {
            _rsa.Dispose();
            throw new InvalidOperationException(
                $"The seal-signing key '{Path.GetFullPath(path)}' (Integrity:SigningKeyPath) doesn't exist. " +
                "Outside Development the app won't generate one: provision the key out of band (see OPERATIONS.md §2), then restart.");
        }

        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var pem = _rsa.ExportRSAPrivateKeyPem();
        File.WriteAllText(path, pem);
        TryRestrictToOwner(path);
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
        foreach (var k in _retired.Values) k.Dispose();
    }
}
