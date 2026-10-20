using System.Security.Cryptography.X509Certificates;
using IncidentManager.Infrastructure.Secrets;
using IncidentManager.Infrastructure.Security;

namespace IncidentManager.Web.Ops;

/// <summary>A certificate CaseBook depends on, what it's for, and when it expires (null when it isn't in the store).</summary>
public sealed record CertificateExpiryItem(string Purpose, string Thumbprint, string? Subject, DateTimeOffset? NotAfter, string Setting);

/// <summary>
/// Finds every certificate the configuration names (the signing key, the chain key, the evidence key's server lock,
/// <c>@protected:</c> values, the CyberArk and syslog client certificates) and, best effort, the TLS certificate: the one
/// in <c>LocalMachine\My</c> whose name matches <c>App:BaseUrl</c>'s host. Read-only. Recovery certificates are
/// watched by the evidence key's own check.
/// </summary>
public sealed class CertificateExpiry(IConfiguration config)
{
    /// <summary>How far ahead an expiry is flagged, as for recovery certificates.</summary>
    public static readonly TimeSpan WarnAhead = TimeSpan.FromDays(60);

    public IReadOnlyList<CertificateExpiryItem> Read() => Read(Uses(config), FindInStore, TlsHost(config), FindTls);

    /// <summary>The certificates <paramref name="uses"/> name, merged by thumbprint, then the TLS one for <paramref name="tlsHost"/>.</summary>
    public static IReadOnlyList<CertificateExpiryItem> Read(
        IEnumerable<(string Purpose, string Setting, string Thumbprint, string Store)> uses,
        Func<string, string, X509Certificate2?> find,
        string? tlsHost,
        Func<string, X509Certificate2?> findTls)
    {
        var items = new List<CertificateExpiryItem>();
        foreach (var group in uses.Where(u => !string.IsNullOrWhiteSpace(u.Thumbprint))
                     .GroupBy(u => (Thumb: CertificateLookup.Normalize(u.Thumbprint), u.Store)))
        {
            using var cert = find(group.Key.Thumb, group.Key.Store);
            items.Add(new CertificateExpiryItem(string.Join(", ", group.Select(u => u.Purpose).Distinct()), group.Key.Thumb,
                cert?.Subject, cert is null ? null : new DateTimeOffset(cert.NotAfter.ToUniversalTime()),
                string.Join(", ", group.Select(u => u.Setting).Distinct())));
        }
        if (!string.IsNullOrWhiteSpace(tlsHost) && findTls(tlsHost) is { } tls)
        {
            using (tls)
            {
                var thumb = CertificateLookup.Normalize(tls.Thumbprint);
                if (!items.Any(i => i.Thumbprint == thumb))
                    items.Add(new CertificateExpiryItem($"TLS, probably (its name matches {tlsHost})", thumb, tls.Subject,
                        new DateTimeOffset(tls.NotAfter.ToUniversalTime()), "IIS binding"));
            }
        }
        return items;
    }

    public static IEnumerable<(string Purpose, string Setting, string Thumbprint, string Store)> Uses(IConfiguration config)
    {
        string Store(string section) => config[$"{section}:StoreLocation"] is { Length: > 0 } s ? s : "LocalMachine";
        if (string.Equals(config["Integrity:SigningKey:Source"], "CertificateStore", StringComparison.OrdinalIgnoreCase))
            yield return ("Seal signing key", "Integrity:SigningKey:CertificateThumbprint", config["Integrity:SigningKey:CertificateThumbprint"] ?? "", Store("Integrity:SigningKey"));
        if (config.GetValue("Integrity:ChainKey:Enabled", false) &&
            string.Equals(config["Integrity:ChainKey:Source"], "Certificate", StringComparison.OrdinalIgnoreCase))
            yield return ("Audit chain key", "Integrity:ChainKey:CertificateThumbprint", config["Integrity:ChainKey:CertificateThumbprint"] ?? "", Store("Integrity:ChainKey"));
        if (config.GetValue("Storage:Encryption:Enabled", false))
            yield return ("Evidence key server lock", "Storage:Encryption:CertificateThumbprint", config["Storage:Encryption:CertificateThumbprint"] ?? "", Store("Storage:Encryption"));
        if (config.GetValue("Secrets:CyberArk:Enabled", false))
            yield return ("CyberArk client certificate", "Secrets:CyberArk:ClientCertificateThumbprint", config["Secrets:CyberArk:ClientCertificateThumbprint"] ?? "", "LocalMachine");
        if (config.GetValue("Siem:Syslog:Enabled", false))
            yield return ("Syslog client certificate", "Siem:Syslog:ClientCertificateThumbprint", config["Siem:Syslog:ClientCertificateThumbprint"] ?? "", "LocalMachine");
        foreach (var key in new[] { "Siem:Webhook:Token", "Chat:Webhook:WebhookUrl", "Email:SmtpPassword" })
            if (ProtectedSecret.ThumbprintOf(config[key]) is { } thumb)
                yield return ($"@protected: value ({key})", key, thumb, "LocalMachine");
    }

    private static string? TlsHost(IConfiguration config) =>
        Uri.TryCreate(config["App:BaseUrl"], UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps ? u.Host : null;

    private static X509Certificate2? FindInStore(string thumbprint, string storeLocation)
    {
        if (!IncidentManager.Domain.Common.EnumNames.TryParse<StoreLocation>(storeLocation, out var location, ignoreCase: true)) return null;
        try
        {
            using var store = new X509Store(StoreName.My, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
            foreach (var other in found.Skip(1)) other.Dispose();
            return found.Count > 0 ? found[0] : null;
        }
        catch (System.Security.Cryptography.CryptographicException) { return null; }
        catch (PlatformNotSupportedException) { return null; }
    }

    // The newest certificate with a private key whose DNS name (or a wildcard) matches the host: IIS's binding isn't
    // readable by the app pool, so this is a guess, and says so.
    private static X509Certificate2? FindTls(string host)
    {
        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2? best = null;
            foreach (var cert in store.Certificates)
            {
                if (cert.HasPrivateKey && cert.MatchesHostname(host, allowWildcards: true) &&
                    (best is null || cert.NotAfter > best.NotAfter))
                {
                    best?.Dispose();
                    best = cert;
                }
                else cert.Dispose();
            }
            return best;
        }
        catch (System.Security.Cryptography.CryptographicException) { return null; }
        catch (PlatformNotSupportedException) { return null; }
    }
}
