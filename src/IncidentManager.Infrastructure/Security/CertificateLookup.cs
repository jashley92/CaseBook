using System.Security.Cryptography.X509Certificates;

namespace IncidentManager.Infrastructure.Security;

/// <summary>Finds a certificate with a usable private key in the Windows certificate store (F-23, F-25).</summary>
public static class CertificateLookup
{
    /// <summary>
    /// The certificate with <paramref name="thumbprint"/> (hex; spaces and other separators ignored) in the <c>My</c>
    /// store at <paramref name="storeLocation"/>, with its private key. Throws a message naming
    /// <paramref name="setting"/> when it's missing, has no readable private key, or isn't RSA. The caller disposes it.
    /// </summary>
    public static X509Certificate2 FindRsa(string thumbprint, string storeLocation, string setting)
    {
        var normalized = Normalize(thumbprint);
        if (normalized.Length == 0)
            throw new InvalidOperationException($"{setting}:CertificateThumbprint is empty.");
        if (!Enum.TryParse<StoreLocation>(storeLocation, ignoreCase: true, out var location))
            throw new InvalidOperationException($"{setting}:StoreLocation '{storeLocation}' isn't LocalMachine or CurrentUser.");

        using var store = new X509Store(StoreName.My, location);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var found = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);
        var cert = found.Count > 0 ? found[0] : null;
        foreach (var other in found.Skip(1)) other.Dispose();
        if (cert is null)
            throw new InvalidOperationException($"No certificate with thumbprint {normalized} in {location}\\My ({setting}:CertificateThumbprint).");
        if (!cert.HasPrivateKey)
        {
            cert.Dispose();
            throw new InvalidOperationException($"The certificate {normalized} in {location}\\My has no private key, or the app account can't read it. Grant it read on the private key.");
        }
        using var probe = cert.GetRSAPublicKey();
        if (probe is null)
        {
            cert.Dispose();
            throw new InvalidOperationException($"The certificate {normalized} isn't an RSA certificate; {setting} needs an RSA key.");
        }
        return cert;
    }

    public static string Normalize(string thumbprint) =>
        new string(thumbprint.Where(char.IsAsciiHexDigit).ToArray()).ToUpperInvariant();
}
