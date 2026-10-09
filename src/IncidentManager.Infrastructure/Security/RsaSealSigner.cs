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
        var spki = _rsa.ExportSubjectPublicKeyInfo();
        KeyId = Convert.ToHexString(SHA256.HashData(spki))[..16].ToLowerInvariant();
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

    public bool Verify(string content, string signatureBase64, string? algorithm = null)
    {
        if (SealAlgorithms.PaddingFor(algorithm) is not { } padding) return false;
        byte[] sig;
        try { sig = Convert.FromBase64String(signatureBase64); }
        catch (FormatException) { return false; }

        return _rsa.VerifyData(Encoding.UTF8.GetBytes(content), sig, HashAlgorithmName.SHA256, padding);
    }

    public void Dispose() => _rsa.Dispose();
}
