using System.Security.Cryptography;
using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// CAP-16: the folder of trusted configuration-bundle keys (<c>Config:TrustedBundleKeys</c>), read once at startup the way
/// the retired seal keys are (F-24): each <c>*.pem</c> is a public key (or a private key, of which only the public half is
/// kept), and a file that isn't a readable RSA key stops startup, so a typo can't quietly leave a source untrusted. Blank
/// means none. A folder that isn't there is an empty list, as for the retired keys.
/// </summary>
public sealed class TrustedBundleKeys : ITrustedBundleKeys
{
    public const string SettingKey = "Config:TrustedBundleKeys";

    public string? Folder { get; }
    public IReadOnlyList<TrustedBundleKey> Keys { get; }

    public TrustedBundleKeys(IConfiguration config) : this(config[SettingKey]) { }

    public TrustedBundleKeys(string? folder)
    {
        if (string.IsNullOrWhiteSpace(folder)) { Keys = []; return; }
        Folder = Path.GetFullPath(folder);
        Keys = Load(Folder);
    }

    private static List<TrustedBundleKey> Load(string folder)
    {
        var keys = new List<TrustedBundleKey>();
        if (!Directory.Exists(folder)) return keys;
        foreach (var file in Directory.EnumerateFiles(folder, "*.pem").Order(StringComparer.Ordinal))
        {
            using var rsa = RSA.Create();
            try
            {
                rsa.ImportFromPem(File.ReadAllText(file));
                var spki = rsa.ExportSubjectPublicKeyInfo();
                using var pub = RSA.Create();
                pub.ImportSubjectPublicKeyInfo(spki, out _);
                var id = RsaSealSigner.KeyIdOf(pub);
                if (keys.Any(k => k.KeyId == id)) continue;   // the same key twice
                keys.Add(new TrustedBundleKey(id, Path.GetFileName(file), pub.ExportSubjectPublicKeyInfoPem()));
            }
            catch (Exception ex) when (ex is ArgumentException or CryptographicException)
            {
                throw new InvalidOperationException(
                    $"'{file}' in the trusted configuration-bundle keys folder ({SettingKey}) isn't a readable RSA key in PEM form. " +
                    "Fix or remove it, then restart.", ex);
            }
        }
        return keys;
    }
}
