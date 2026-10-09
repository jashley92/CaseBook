using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// F-25: loads the audit chain keys once, at startup, from CyberArk or from files encrypted to a certificate, and holds
/// them in memory. Off (empty) unless <c>Integrity:ChainKey:Enabled</c>. A key that can't be loaded stops startup: with
/// the chain key on, the app mustn't write entries it couldn't later check.
/// </summary>
public sealed class ChainKeyring : IChainKeyring
{
    private const int KeyBytes = 32;
    private readonly Dictionary<string, byte[]> _keys = new(StringComparer.OrdinalIgnoreCase);

    public string? CurrentKeyId { get; }
    public IReadOnlyList<string> KeyIds { get; }
    public string? Source { get; }

    public ChainKeyring(IOptions<SealSigningOptions> options, ISecretProvider? secrets = null)
    {
        var o = options.Value;
        var k = o.ChainKey;
        if (!k.Enabled)
        {
            KeyIds = [];
            return;
        }

        var (current, retired, source) = k.Source switch
        {
            ChainKeySource.Certificate => FromCertificate(k, KeysFolder(o)),
            _ => FromCyberArk(k, secrets)
        };
        CurrentKeyId = KeyIdOf(current);
        _keys[CurrentKeyId] = current;
        foreach (var r in retired) _keys.TryAdd(KeyIdOf(r), r);
        KeyIds = [CurrentKeyId, .. _keys.Keys.Where(id => id != CurrentKeyId).Order(StringComparer.Ordinal)];
        Source = source;
    }

    public byte[]? Key(string keyId) => _keys.GetValueOrDefault(keyId);

    /// <summary>A key's id: the first 16 hex characters of an HMAC of a fixed label under the key. Reveals nothing about it.</summary>
    public static string KeyIdOf(byte[] key) =>
        Convert.ToHexString(HMACSHA256.HashData(key, "CaseBook audit chain key id"u8))[..16].ToLowerInvariant();

    private static string KeysFolder(SealSigningOptions o) =>
        Path.GetDirectoryName(Path.GetFullPath(o.SigningKeyPath)) ?? ".";

    private static (byte[], List<byte[]>, string) FromCyberArk(ChainKeyOptions k, ISecretProvider? secrets)
    {
        if (secrets is null)
            throw new InvalidOperationException("Integrity:ChainKey:Source is CyberArk but no secret provider is available.");
        var current = FetchKey(k.Secret, "Integrity:ChainKey:Secret", secrets);
        var retired = k.RetiredSecrets.Select((r, i) => FetchKey(r, $"Integrity:ChainKey:RetiredSecrets:{i}", secrets)).ToList();
        return (current, retired, "CyberArk");
    }

    private static byte[] FetchKey(string reference, string setting, ISecretProvider secrets)
    {
        if (string.IsNullOrWhiteSpace(reference) || !reference.TrimStart().StartsWith("@cyberark:", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"{setting} must be an @cyberark:Safe=…;Object=… reference; the key itself never goes in configuration.");
        var value = secrets.ResolveAsync(reference).AsTask().GetAwaiter().GetResult();
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException($"The audit chain key couldn't be fetched from CyberArk ({setting}). " +
                "Check Secrets:CyberArk is enabled and Administration → Diagnostics → Secret resolution.");
        byte[] key;
        try { key = Convert.FromBase64String(value.Trim()); }
        catch (FormatException) { throw new InvalidOperationException($"The secret for {setting} isn't base64. Store 32 random bytes, base64-encoded."); }
        if (key.Length < KeyBytes)
            throw new InvalidOperationException($"The secret for {setting} is {key.Length} bytes; the chain key needs at least {KeyBytes}.");
        return key;
    }

    // The key file is JSON: the thumbprint of the certificate it's encrypted to, and the RSA-OAEP-SHA256 ciphertext.
    private sealed record WrappedKey(string Thumbprint, string Wrapped);

    private static (byte[], List<byte[]>, string) FromCertificate(ChainKeyOptions k, string keysFolder)
    {
        var path = string.IsNullOrWhiteSpace(k.WrappedKeyPath) ? Path.Combine(keysFolder, "chain-key.json") : k.WrappedKeyPath;
        var retiredFolder = string.IsNullOrWhiteSpace(k.RetiredWrappedKeysPath) ? Path.Combine(keysFolder, "chain-retired") : k.RetiredWrappedKeysPath;
        using var cert = CertificateLookup.FindRsa(k.CertificateThumbprint, k.StoreLocation, "Integrity:ChainKey");

        byte[] current;
        if (File.Exists(path))
            current = Unwrap(path, k.StoreLocation, cert);
        else
        {
            // First start with the chain key on: make the key and keep only its encrypted form on disk.
            current = RandomNumberGenerator.GetBytes(KeyBytes);
            using var pub = cert.GetRSAPublicKey()!;
            var record = new WrappedKey(cert.Thumbprint, Convert.ToBase64String(pub.Encrypt(current, RSAEncryptionPadding.OaepSHA256)));
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            File.WriteAllText(path, JsonSerializer.Serialize(record));
        }

        var retired = Directory.Exists(retiredFolder)
            ? Directory.EnumerateFiles(retiredFolder, "*.json").Order(StringComparer.Ordinal)
                .Select(f => Unwrap(f, k.StoreLocation, cert)).ToList()
            : [];
        return (current, retired, $"Certificate ({CertificateLookup.Normalize(cert.Thumbprint)}), {Path.GetFullPath(path)}");
    }

    // A file names the certificate it was encrypted to; that may be an earlier certificate still in the store.
    private static byte[] Unwrap(string file, string storeLocation, X509Certificate2 configured)
    {
        WrappedKey? record;
        try { record = JsonSerializer.Deserialize<WrappedKey>(File.ReadAllText(file)); }
        catch (JsonException ex) { throw new InvalidOperationException($"The chain key file '{file}' isn't readable.", ex); }
        if (record is null || string.IsNullOrEmpty(record.Wrapped))
            throw new InvalidOperationException($"The chain key file '{file}' is empty.");

        var same = string.Equals(CertificateLookup.Normalize(record.Thumbprint), CertificateLookup.Normalize(configured.Thumbprint), StringComparison.Ordinal);
        using var other = same ? null : CertificateLookup.FindRsa(record.Thumbprint, storeLocation, $"The chain key file '{file}'");
        using var rsa = (same ? configured : other!).GetRSAPrivateKey()!;
        try { return rsa.Decrypt(Convert.FromBase64String(record.Wrapped), RSAEncryptionPadding.OaepSHA256); }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new InvalidOperationException($"The chain key file '{file}' can't be decrypted with certificate {record.Thumbprint}.", ex);
        }
    }
}
