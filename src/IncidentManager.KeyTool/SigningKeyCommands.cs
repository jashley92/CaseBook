using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using IncidentManager.Infrastructure.Security;

namespace IncidentManager.KeyTool;

/// <summary>
/// The seal-signing key (OPERATIONS.md section 2), for what Windows PowerShell 5.1 can't do on its own: make a key as a PEM
/// file, wrap an existing PEM in a certificate for the certificate store (keeping its key id), and write the public half
/// of a key for the retired keys folder or an examiner. None of them changes a site.
/// </summary>
internal static class SigningKeyCommands
{
    public const int KeySizeBits = 3072;

    /// <summary>
    /// new-signing-key: an RSA-3072 private key in PEM (PKCS#8) at <paramref name="outPath"/>, readable only by the account
    /// running the tool, and its public half beside it as <c>&lt;name&gt;.public.pem</c>. Returns the key id.
    /// </summary>
    public static string NewKey(string outPath, TextWriter output)
    {
        var path = Path.GetFullPath(outPath);
        var publicPath = PublicPathFor(path);
        foreach (var p in new[] { path, publicPath })
            if (File.Exists(p)) throw new InvalidOperationException($"{p} already exists; nothing was written.");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        using var rsa = RSA.Create(KeySizeBits);
        var keyId = RsaSealSigner.KeyIdOf(rsa);
        WritePrivate(path, rsa.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(publicPath, rsa.ExportSubjectPublicKeyInfoPem());
        output.WriteLine($"Seal-signing key {keyId} (RSA {KeySizeBits}):");
        output.WriteLine($"  private key: {path} (readable by this account only)");
        output.WriteLine($"  public key:  {publicPath}");
        output.WriteLine("Install the private key (OPERATIONS.md section 2), record the key id, keep the public key with your key " +
                         "inventory, and delete the private key from this machine once it's installed.");
        return keyId;
    }

    /// <summary>
    /// signing-key-pfx: the PEM private key at <paramref name="pemPath"/> in a self-signed certificate, as a password-protected
    /// PFX for Import-PfxCertificate. The key, and so the key id, is the PEM's. Returns the key id.
    /// </summary>
    public static string ToPfx(string pemPath, string outPath, string password, TextWriter output)
    {
        if (string.IsNullOrEmpty(password)) throw new ArgumentException("The PFX password is empty.");
        var path = Path.GetFullPath(outPath);
        if (File.Exists(path)) throw new InvalidOperationException($"{path} already exists; nothing was written.");
        using var rsa = ReadPrivate(pemPath);
        var keyId = RsaSealSigner.KeyIdOf(rsa);
        var request = new CertificateRequest($"CN=CaseBook seal signing {keyId}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        // Nothing checks this certificate's dates or chain (trust comes from the key id), so it's made to outlast the key.
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(25));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        WritePrivate(path, cert.Export(X509ContentType.Pfx, password));
        output.WriteLine($"{path}: seal-signing key {keyId} in certificate {cert.Thumbprint}.");
        output.WriteLine("Import it on the server into LocalMachine\\My (not exportable), give the app-pool account read on its " +
                         "private key, and set Integrity:SigningKey (OPERATIONS.md section 2). Delete the PFX afterwards.");
        return keyId;
    }

    /// <summary>
    /// signing-public-key: the public half of a key, in PEM (SubjectPublicKeyInfo), from a PEM file, a certificate in the
    /// store, or the key a site is configured with. Returns (key id, PEM).
    /// </summary>
    public static (string KeyId, string Pem) PublicKey(string? pemPath, string? thumbprint, string store, Site? site)
    {
        if (site is not null)
        {
            var k = site.Integrity.SigningKey;
            switch (k.Source)
            {
                case SigningKeySource.CertificateStore: thumbprint = k.CertificateThumbprint; store = k.StoreLocation; break;
                case SigningKeySource.CyberArk:
                    throw new InvalidOperationException("The site's signing key is in CyberArk, which the tool doesn't fetch from. Use " +
                        "signing-public-key --pem with the PEM from the vault, or signing-public-key.pem from a compliance bundle.");
                default: pemPath = site.SigningKeyPath; break;
            }
        }
        using var rsa = thumbprint is not null ? FromCertificate(thumbprint, store)
            : pemPath is not null ? ReadPrivateOrPublic(pemPath)
            : throw new ArgumentException("Give --site <folder>, --pem <file> or --cert <thumbprint>.");
        return (RsaSealSigner.KeyIdOf(rsa), rsa.ExportSubjectPublicKeyInfoPem());
    }

    internal static string PublicPathFor(string privatePath) =>
        Path.Combine(Path.GetDirectoryName(privatePath)!, Path.GetFileNameWithoutExtension(privatePath) + ".public.pem");

    private static RSA FromCertificate(string thumbprint, string store)
    {
        using var cert = CertificateLookup.FindPublic(thumbprint, store, "--cert");
        return cert.GetRSAPublicKey() ?? throw new InvalidOperationException($"The certificate {CertificateLookup.Normalize(thumbprint)} isn't an RSA certificate.");
    }

    private static RSA ReadPrivate(string pemPath)
    {
        var rsa = ReadPrivateOrPublic(pemPath);
        try
        {
            rsa.ExportParameters(includePrivateParameters: true);
            return rsa;
        }
        catch (CryptographicException)
        {
            rsa.Dispose();
            throw new InvalidOperationException($"{Path.GetFullPath(pemPath)} holds a public key only; a PFX needs the private key.");
        }
    }

    private static RSA ReadPrivateOrPublic(string pemPath)
    {
        var path = Path.GetFullPath(pemPath);
        if (!File.Exists(path)) throw new InvalidOperationException($"{path} doesn't exist.");
        var rsa = RSA.Create();
        try { rsa.ImportFromPem(File.ReadAllText(path)); }
        catch (ArgumentException)
        {
            rsa.Dispose();
            throw new InvalidOperationException($"{path} isn't an RSA key in PEM form.");
        }
        if (rsa.KeySize < 2048)
        {
            rsa.Dispose();
            throw new InvalidOperationException($"{path} is a {rsa.KeySize}-bit key; CaseBook needs RSA 2048 bits or more.");
        }
        return rsa;
    }

    private static void WritePrivate(string path, string text) => WritePrivate(path, System.Text.Encoding.ASCII.GetBytes(text));

    // Created readable by this account alone, so the key is never readable by anyone else, even for a moment.
    private static void WritePrivate(string path, byte[] bytes)
    {
        if (OperatingSystem.IsWindows())
        {
            var security = new System.Security.AccessControl.FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var me = System.Security.Principal.WindowsIdentity.GetCurrent().User
                ?? throw new InvalidOperationException("The account running the tool has no security id.");
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(me,
                System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
            using var file = System.IO.FileSystemAclExtensions.Create(new FileInfo(path), FileMode.CreateNew,
                System.Security.AccessControl.FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, security);
            file.Write(bytes);
        }
        else
        {
            using var file = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });
            file.Write(bytes);
        }
    }
}
