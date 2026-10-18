using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IncidentManager.Infrastructure.Security;

namespace IncidentManager.Infrastructure.Secrets;

/// <summary>
/// CAP-05 (ADR 0018): a secret written in configuration encrypted to a certificate in the Windows store, for a site
/// without CyberArk. <c>@protected:v1:&lt;thumbprint&gt;:&lt;base64&gt;</c>, where the base64 is a random AES-256-GCM key
/// wrapped to the certificate's RSA key with OAEP-SHA256, then the GCM nonce, tag and ciphertext. The version and the
/// thumbprint are the GCM associated data, so neither can be changed without the value failing to open. Only the
/// certificate's private key opens it: the value is useless off the server, and no new key material is kept in
/// configuration (the pattern the chain key's file uses, ADR 0016). Made with <c>casebook-keytool protect-secret</c>.
/// </summary>
public static class ProtectedSecret
{
    public const string Scheme = "@protected:";
    private const string Version = "v1";
    private const int KeyBytes = 32;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;

    /// <summary>True if <paramref name="value"/> is a <c>@protected:</c> value rather than a literal (leading space allowed, REV-10).</summary>
    public static bool IsProtected([NotNullWhen(true)] string? value) =>
        value is not null && value.TrimStart().StartsWith(Scheme, StringComparison.OrdinalIgnoreCase);

    /// <summary>Encrypts <paramref name="secret"/> to <paramref name="certificate"/>'s public key. Needs no private key.</summary>
    public static string Protect(string secret, X509Certificate2 certificate)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        using var rsa = certificate.GetRSAPublicKey()
            ?? throw new InvalidOperationException($"The certificate {CertificateLookup.Normalize(certificate.Thumbprint)} isn't an RSA certificate.");
        var thumbprint = CertificateLookup.Normalize(certificate.Thumbprint);
        var key = RandomNumberGenerator.GetBytes(KeyBytes);
        var plain = Encoding.UTF8.GetBytes(secret);
        try
        {
            var wrapped = rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA256);
            var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
            var tag = new byte[TagBytes];
            var cipher = new byte[plain.Length];
            using (var gcm = new AesGcm(key, TagBytes)) gcm.Encrypt(nonce, plain, cipher, tag, Aad(thumbprint));
            return $"{Scheme}{Version}:{thumbprint}:{Convert.ToBase64String([.. wrapped, .. nonce, .. tag, .. cipher])}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <summary>The thumbprint a value names (a label for logs and Diagnostics; not secret), or null when it doesn't parse.</summary>
    public static string? ThumbprintOf(string? value) => Parse(value, out var thumbprint, out _, out _) ? thumbprint : null;

    /// <summary>
    /// Opens a value with the certificate <paramref name="findCertificate"/> gives for its thumbprint (the caller's lookup
    /// throws <see cref="InvalidOperationException"/> when it isn't there). False, with a reason that names no part of the
    /// secret, when the value is malformed, of an unknown version, its certificate can't be had, or it was changed.
    /// </summary>
    public static bool TryOpen(string value, Func<string, X509Certificate2> findCertificate,
        [NotNullWhen(true)] out string? secret, [NotNullWhen(false)] out string? reason)
    {
        secret = null;
        if (!Parse(value, out var thumbprint, out var blob, out reason)) return false;

        X509Certificate2 cert;
        try { cert = findCertificate(thumbprint); }
        catch (InvalidOperationException ex)
        {
            reason = ex.Message;
            return false;
        }
        using (cert)
        {
            using var rsa = cert.GetRSAPrivateKey();
            if (rsa is null)
            {
                reason = $"the certificate {thumbprint} has no RSA private key this account can read";
                return false;
            }
            var wrappedLength = rsa.KeySize / 8;
            if (blob.Length < wrappedLength + NonceBytes + TagBytes)
            {
                reason = "the value is too short to be one made for this certificate";
                return false;
            }
            byte[]? key = null;
            try
            {
                key = rsa.Decrypt(blob.AsSpan(0, wrappedLength).ToArray(), RSAEncryptionPadding.OaepSHA256);
                if (key.Length != KeyBytes) throw new CryptographicException();
                var at = wrappedLength;
                var nonce = blob.AsSpan(at, NonceBytes);
                var tag = blob.AsSpan(at + NonceBytes, TagBytes);
                var cipher = blob.AsSpan(at + NonceBytes + TagBytes);
                var plain = new byte[cipher.Length];
                using (var gcm = new AesGcm(key, TagBytes)) gcm.Decrypt(nonce, cipher, tag, plain, Aad(thumbprint));
                secret = Encoding.UTF8.GetString(plain);
                CryptographicOperations.ZeroMemory(plain);
                return true;
            }
            catch (CryptographicException)
            {
                // The wrapped key isn't this certificate's (a value made for another one), or a byte was changed.
                reason = $"the value doesn't open with the certificate {thumbprint}: it was made for another key or changed since";
                return false;
            }
            finally
            {
                if (key is not null) CryptographicOperations.ZeroMemory(key);
            }
        }
    }

    /// <summary>
    /// The certificate for a value's thumbprint, with its private key: <c>LocalMachine\My</c> (where the server keeps
    /// it), then the account's own <c>CurrentUser\My</c>. Throws <see cref="InvalidOperationException"/> when neither has it.
    /// </summary>
    public static X509Certificate2 FindInStore(string thumbprint)
    {
        try { return CertificateLookup.FindRsa(thumbprint, "LocalMachine", "@protected:"); }
        catch (InvalidOperationException machine)
        {
            try { return CertificateLookup.FindRsa(thumbprint, "CurrentUser", "@protected:"); }
            catch (InvalidOperationException)
            {
                throw new InvalidOperationException($"the certificate {thumbprint} isn't in LocalMachine\\My (or CurrentUser\\My) " +
                                                    $"with a private key this account can read ({machine.Message})", machine);
            }
        }
    }

    private static byte[] Aad(string thumbprint) => Encoding.ASCII.GetBytes($"CaseBook {Scheme}{Version}:{thumbprint}");

    private static bool Parse(string? value, [NotNullWhen(true)] out string? thumbprint, [NotNullWhen(true)] out byte[]? blob,
        [NotNullWhen(false)] out string? reason)
    {
        thumbprint = null;
        blob = null;
        if (!IsProtected(value))
        {
            reason = "it isn't a @protected: value";
            return false;
        }
        var parts = value.Trim()[Scheme.Length..].Split(':');
        if (parts.Length != 3)
        {
            reason = "it isn't in the form @protected:v1:<thumbprint>:<data>";
            return false;
        }
        if (!string.Equals(parts[0], Version, StringComparison.OrdinalIgnoreCase))
        {
            reason = $"its version '{parts[0]}' isn't one this CaseBook reads (v1)";
            return false;
        }
        var normalized = CertificateLookup.Normalize(parts[1]);
        if (normalized.Length != 40 || normalized.Length != parts[1].Length)
        {
            reason = "its certificate thumbprint isn't 40 hex characters";
            return false;
        }
        try { blob = Convert.FromBase64String(parts[2]); }
        catch (FormatException)
        {
            reason = "its data isn't base64";
            return false;
        }
        thumbprint = normalized;
        reason = null;
        return true;
    }
}
