using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// PROD-57: evidence encryption (server configuration, section <c>Storage:Encryption</c>; ADR 0007, 0016 and 0017).
/// </summary>
public sealed class EvidenceEncryptionOptions
{
    /// <summary>Whether evidence and reports are encrypted at rest. Off until an administrator turns it on.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Optional: a certificate (LocalMachine\My by default) to protect the evidence key with, kept apart from the audit
    /// chain's. Blank uses the integrity certificate already configured: the chain key's, else the seal-signing
    /// certificate; with the chain key from CyberArk, a key derived from it.
    /// </summary>
    public string CertificateThumbprint { get; set; } = "";

    public string StoreLocation { get; set; } = "LocalMachine";

    /// <summary>
    /// Recovery certificates: paths to .cer files (the public part only). The evidence key (and the chain key, when it's
    /// on) is also encrypted to each, so whoever holds one's private key offline can recover it without this server.
    /// </summary>
    public string[] RecoveryCertificates { get; set; } = [];

    /// <summary>The envelope file; blank is <c>evidence-key.json</c> beside the seal-signing key.</summary>
    public string EnvelopePath { get; set; } = "";
}

/// <summary>
/// PROD-57: the evidence key in its encrypted forms, written to the keys folder, the database and beside the evidence.
/// It never holds the key itself: a copy opens only with the server's protection (its certificate, or the CyberArk
/// chain key), a recovery certificate's private key, or enough shares.
/// </summary>
public sealed class KeyEnvelope
{
    public int Version { get; set; } = 1;
    public string KeyId { get; set; } = "";
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset UpdatedUtc { get; set; }

    /// <summary>The key encrypted with the server's protection.</summary>
    public WrappedKey Server { get; set; } = new();

    /// <summary>The key (and the chain key, when on) encrypted to each recovery certificate.</summary>
    public List<RecoveryCopy> Recovery { get; set; } = [];

    /// <summary>That shares were issued (by casebook-keytool split): when, how many, how many needed. Never the shares.</summary>
    public SharesIssued? Shares { get; set; }

    /// <summary>The last recovery drill (casebook-keytool verify) that opened this envelope from a backup.</summary>
    public DateTimeOffset? LastDrillUtc { get; set; }
    public string? LastDrillBy { get; set; }

    /// <summary>
    /// PROD-59: what casebook-keytool did (shares issued, a drill, a recovery, an export). The tool runs apart from the
    /// app and can't write the audit trail, so it leaves a record here; CaseBook writes each to the audit trail and the
    /// SIEM once, when it next reads the envelope. The newest <see cref="MaxRecords"/> are kept.
    /// </summary>
    public List<KeyToolRecord> Records { get; set; } = [];

    public const int MaxRecords = 200;

    /// <summary>Adds a record, keeping the newest <see cref="MaxRecords"/>.</summary>
    public void Record(string kind, string summary, string? caseNumber = null)
    {
        Records.Add(new KeyToolRecord
        {
            Id = Guid.NewGuid(), Kind = kind, AtUtc = DateTimeOffset.UtcNow,
            By = $"{Environment.UserDomainName}\\{Environment.UserName}", Summary = summary, CaseNumber = caseNumber,
        });
        if (Records.Count > MaxRecords) Records = Records.OrderByDescending(r => r.AtUtc).Take(MaxRecords).OrderBy(r => r.AtUtc).ToList();
    }

    [JsonIgnore] public bool HasBackup => Recovery.Count > 0 || Shares is not null;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    /// <summary>The envelope in <paramref name="json"/>, or null when it isn't one (damaged, or not an envelope).</summary>
    public static KeyEnvelope? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            var e = JsonSerializer.Deserialize<KeyEnvelope>(json, Json);
            return e is { Version: 1, KeyId.Length: 16 } && e.Server.Data.Length > 0 ? e : null;
        }
        catch (JsonException) { return null; }
    }
}

/// <summary>The key encrypted one way: to a certificate (RSA-OAEP-SHA256) or under the chain key (AES-GCM).</summary>
public sealed class WrappedKey
{
    public const string Certificate = "certificate", ChainKey = "chain-key";

    public string Kind { get; set; } = "";

    /// <summary>The certificate's thumbprint, or the chain key's id.</summary>
    public string Ref { get; set; } = "";

    public string Data { get; set; } = "";
}

public sealed class RecoveryCopy
{
    public string Thumbprint { get; set; } = "";
    public string Subject { get; set; } = "";
    public DateTimeOffset NotAfter { get; set; }

    /// <summary>The recovery payload (<see cref="KeyWrap.Pack"/>) encrypted to the certificate.</summary>
    public string Data { get; set; } = "";

    /// <summary>The chain key it also carries, by id; null when the chain key was off.</summary>
    public string? ChainKeyId { get; set; }
}

/// <summary>PROD-59: one thing casebook-keytool did, for CaseBook to record (see <see cref="KeyEnvelope.Records"/>).</summary>
public sealed class KeyToolRecord
{
    public const string SharesIssued = "shares-issued", Drill = "drill", Recovered = "recovered", Exported = "exported",
        CustodianRetired = "custodian-retired";

    public Guid Id { get; set; }
    public string Kind { get; set; } = "";
    public DateTimeOffset AtUtc { get; set; }
    public string By { get; set; } = "";
    public string Summary { get; set; } = "";
    public string? CaseNumber { get; set; }
}

public sealed class SharesIssued
{
    public DateTimeOffset IssuedUtc { get; set; }
    public int Threshold { get; set; }
    public int Count { get; set; }
    public string? ChainKeyId { get; set; }
}

/// <summary>PROD-57: the evidence key's encryptions, and its id.</summary>
public static class KeyWrap
{
    public const int KeySize = 32;

    /// <summary>A key's id: 16 hex digits of an HMAC of a fixed label under it. Reveals nothing about the key.</summary>
    public static string KeyIdOf(byte[] key) =>
        Convert.ToHexString(HMACSHA256.HashData(key, "CaseBook evidence key id"u8))[..16].ToLowerInvariant();

    public static string ToCertificate(X509Certificate2 cert, byte[] data)
    {
        using var rsa = cert.GetRSAPublicKey() ?? throw new InvalidOperationException($"Certificate {cert.Thumbprint} has no RSA key.");
        return Convert.ToBase64String(rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256));
    }

    /// <summary>Opens data encrypted to <paramref name="cert"/> with its private key; throws CryptographicException if it can't.</summary>
    public static byte[] FromCertificate(X509Certificate2 cert, string data)
    {
        using var rsa = cert.GetRSAPrivateKey() ?? throw new CryptographicException($"The private key of certificate {cert.Thumbprint} isn't available.");
        return rsa.Decrypt(Convert.FromBase64String(data), RSAEncryptionPadding.OaepSHA256);
    }

    // The chain key itself never encrypts the evidence key: a key derived from it for this one use does.
    private static byte[] Derived(byte[] chainKey) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, chainKey, KeySize, info: "CaseBook evidence key wrap"u8.ToArray());

    public static string UnderChainKey(byte[] chainKey, byte[] data)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var sealedData = new byte[data.Length];
        var tag = new byte[16];
        using (var gcm = new AesGcm(Derived(chainKey), 16)) gcm.Encrypt(nonce, data, sealedData, tag, "CaseBook evidence key"u8);
        return Convert.ToBase64String([.. nonce, .. sealedData, .. tag]);
    }

    public static byte[] FromChainKey(byte[] chainKey, string data)
    {
        var raw = Convert.FromBase64String(data);
        if (raw.Length < 12 + 16) throw new CryptographicException("The wrapped key is too short.");
        var plain = new byte[raw.Length - 28];
        using var gcm = new AesGcm(Derived(chainKey), 16);
        gcm.Decrypt(raw.AsSpan(0, 12), raw.AsSpan(12, plain.Length), raw.AsSpan(raw.Length - 16), plain, "CaseBook evidence key"u8);
        return plain;
    }

    /// <summary>What a recovery copy or the shares carry: the evidence key, and the chain key when it's on.</summary>
    public static byte[] Pack(byte[] evidenceKey, byte[]? chainKey)
    {
        chainKey ??= [];
        if (evidenceKey.Length > 255 || chainKey.Length > 255) throw new ArgumentException("A key is too long to pack.");
        return [1, (byte)evidenceKey.Length, .. evidenceKey, (byte)chainKey.Length, .. chainKey];
    }

    public static (byte[] EvidenceKey, byte[]? ChainKey) Unpack(byte[] packed)
    {
        if (packed.Length < 3 || packed[0] != 1) throw new CryptographicException("Not a CaseBook key package.");
        var ek = packed.AsSpan(2, packed[1]).ToArray();
        var at = 2 + packed[1];
        var ckLength = packed[at];
        if (packed.Length != at + 1 + ckLength) throw new CryptographicException("The key package is damaged.");
        return (ek, ckLength == 0 ? null : packed.AsSpan(at + 1, ckLength).ToArray());
    }
}
