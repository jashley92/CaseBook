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
        // A store that can't be opened (LocalMachine\My off Windows, one this account can't read) is "not found here",
        // in the same words, so callers that try one store after another carry on (casebook-keytool, PROD-57).
        try { store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly); }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            throw new InvalidOperationException($"The {location}\\My certificate store can't be opened here ({ex.Message}); " +
                                                $"{setting}:CertificateThumbprint can't be found in it.", ex);
        }
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

    /// <summary>
    /// CAP-05: the certificate with <paramref name="thumbprint"/> in <paramref name="storeLocation"/>\My for its RSA public key
    /// only (encrypting to it, as <c>casebook-keytool protect-secret</c> does, needs no private key, so an administrator can
    /// protect a secret for a key only the app-pool account may read). Throws as <see cref="FindRsa"/> does. The caller
    /// disposes it.
    /// </summary>
    public static X509Certificate2 FindPublic(string thumbprint, string storeLocation, string setting)
    {
        var normalized = Normalize(thumbprint);
        if (normalized.Length == 0) throw new InvalidOperationException($"{setting} is empty.");
        // C16: by name only (a number isn't a store).
        if (!IncidentManager.Domain.Common.EnumNames.TryParse<StoreLocation>(storeLocation, out var location, ignoreCase: true))
            throw new InvalidOperationException($"'{storeLocation}' isn't LocalMachine or CurrentUser.");
        using var store = new X509Store(StoreName.My, location);
        try { store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly); }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            throw new InvalidOperationException($"The {location}\\My certificate store can't be opened here ({ex.Message}).", ex);
        }
        var found = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);
        var cert = found.Count > 0 ? found[0] : null;
        foreach (var other in found.Skip(1)) other.Dispose();
        if (cert is null) throw new InvalidOperationException($"No certificate with thumbprint {normalized} in {location}\\My ({setting}).");
        using var probe = cert.GetRSAPublicKey();
        if (probe is null)
        {
            cert.Dispose();
            throw new InvalidOperationException($"The certificate {normalized} isn't an RSA certificate.");
        }
        return cert;
    }

    public static string Normalize(string thumbprint) =>
        new string(thumbprint.Where(char.IsAsciiHexDigit).ToArray()).ToUpperInvariant();
}
