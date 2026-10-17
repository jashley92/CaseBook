using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// PROD-57: opens an evidence-key envelope from one of its backups, for casebook-keytool and tests: the server certificate
/// (by the thumbprint the envelope names), a recovery certificate with its private key, or enough shares. Every way checks
/// the key it gets has the envelope's key id, so a wrong certificate, a mixed-up share set or a damaged copy is refused
/// rather than used. Read-only: it never makes a key.
/// </summary>
public static class EnvelopeOpener
{
    public sealed record Opened(byte[] EvidenceKey, byte[]? ChainKey, string How);

    /// <summary>With the server certificate the envelope names, from LocalMachine\My or CurrentUser\My.</summary>
    public static Opened WithServerCertificate(KeyEnvelope e)
    {
        if (e.Server.Kind != WrappedKey.Certificate)
            throw new InvalidOperationException("This envelope is protected by the audit chain key from CyberArk, not a certificate. " +
                                                "Open it with a recovery certificate (--pfx or --cert) or the shares (--shares).");
        foreach (var store in new[] { "LocalMachine", "CurrentUser" })
        {
            X509Certificate2 cert;
            try { cert = CertificateLookup.FindRsa(e.Server.Ref, store, "the envelope's server certificate"); }
            catch (InvalidOperationException) { continue; }
            using (cert)
            {
                var key = KeyWrap.FromCertificate(cert, e.Server.Data);
                return Checked(e, key, null, $"server certificate {e.Server.Ref} ({store})");
            }
        }
        throw new InvalidOperationException($"The server certificate {e.Server.Ref} isn't in LocalMachine\\My or CurrentUser\\My on this machine " +
                                            "(or this account can't use its private key). Run as an administrator on the CaseBook server, or use a backup.");
    }

    /// <summary>With a recovery certificate's private key (a PFX, or one in a store or on a smartcard).</summary>
    public static Opened WithRecoveryCertificate(KeyEnvelope e, X509Certificate2 withPrivateKey)
    {
        var thumb = CertificateLookup.Normalize(withPrivateKey.Thumbprint);
        var copy = e.Recovery.FirstOrDefault(r => string.Equals(r.Thumbprint, thumb, StringComparison.OrdinalIgnoreCase))
                   ?? throw new InvalidOperationException($"This envelope has no copy for certificate {thumb}. Its recovery certificates are: " +
                                                          string.Join(", ", e.Recovery.Select(r => $"{r.Thumbprint} ({r.Subject})")));
        var (key, chain) = KeyWrap.Unpack(KeyWrap.FromCertificate(withPrivateKey, copy.Data));
        return Checked(e, key, chain, $"recovery certificate {thumb} ({withPrivateKey.Subject})");
    }

    /// <summary>With enough shares (they carry the key id, which must be this envelope's).</summary>
    public static Opened WithShares(KeyEnvelope e, IReadOnlyCollection<string> shares)
    {
        var (key, chain) = KeyWrap.Unpack(KeyShares.Combine(shares));
        if (shares.Count > 0 && KeyShares.Decode(shares.First()).KeyId != e.KeyId)
            throw new InvalidOperationException($"These shares are for key {KeyShares.Decode(shares.First()).KeyId}, not this envelope's {e.KeyId}.");
        return Checked(e, key, chain, $"{shares.Count} shares");
    }

    private static Opened Checked(KeyEnvelope e, byte[] key, byte[]? chain, string how)
    {
        if (KeyWrap.KeyIdOf(key) != e.KeyId)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new CryptographicException($"The key opened with {how} isn't this envelope's key ({e.KeyId}).");
        }
        return new Opened(key, chain, how);
    }
}
