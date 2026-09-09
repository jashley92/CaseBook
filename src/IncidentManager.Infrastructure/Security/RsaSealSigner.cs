using System.Security.Cryptography;
using System.Text;
using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// Signs integrity seals with RSA (RSASSA-PKCS1-v1_5 over SHA-256). The private key is loaded from
/// the configured PEM file, or generated and persisted there on first use so seals remain verifiable
/// across restarts. This is a genuine asymmetric signature — a substantial step up from a keyed hash
/// — but the key still lives on disk; production should provision it via DPAPI / the Windows cert
/// store / an HSM rather than let the app generate it.
/// </summary>
public sealed class RsaSealSigner : ISealSigner, IDisposable
{
    private const int KeySizeBits = 3072;
    private readonly RSA _rsa;

    public string Algorithm => "RSASSA-PKCS1-v1_5-SHA256";
    public string KeyId { get; }

    /// <summary>The public key in PEM (SubjectPublicKeyInfo) form for independent, offline verification.</summary>
    public string PublicKeyPem => _rsa.ExportSubjectPublicKeyInfoPem();

    public RsaSealSigner(IOptions<SealSigningOptions> options)
    {
        var path = options.Value.SigningKeyPath;
        _rsa = RSA.Create(KeySizeBits);
        LoadOrCreateKey(path);

        // Thumbprint the public key so a seal can record which key signed it.
        var spki = _rsa.ExportSubjectPublicKeyInfo();
        KeyId = Convert.ToHexString(SHA256.HashData(spki))[..16].ToLowerInvariant();
    }

    private void LoadOrCreateKey(string path)
    {
        if (File.Exists(path))
        {
            _rsa.ImportFromPem(File.ReadAllText(path));
            return;
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
        var sig = _rsa.SignData(Encoding.UTF8.GetBytes(content), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(sig);
    }

    public bool Verify(string content, string signatureBase64)
    {
        byte[] sig;
        try { sig = Convert.FromBase64String(signatureBase64); }
        catch (FormatException) { return false; }

        return _rsa.VerifyData(Encoding.UTF8.GetBytes(content), sig,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public void Dispose() => _rsa.Dispose();
}
