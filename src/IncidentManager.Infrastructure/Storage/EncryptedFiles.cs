using System.Security.Cryptography;
using IncidentManager.Application.Abstractions;

namespace IncidentManager.Infrastructure.Storage;

/// <summary>
/// PROD-57: what the evidence and report stores share for encryption at rest: whether a new file is encrypted (only when
/// the keyring is <see cref="EvidenceKeyState.Ready"/>), and opening a file either way, since files written before
/// encryption was on, or before their conversion, are plain. One reader for both formats (C4).
/// </summary>
public static class EncryptedFiles
{
    /// <summary>
    /// The key a new file is encrypted with, or null to store it as it is (encryption off, not configured, or waiting for
    /// a backup). While the key is needed but unavailable, a new file is refused rather than stored unencrypted.
    /// </summary>
    public static (string KeyId, byte[] Key)? ForNewFile(IEvidenceKeyring keys)
    {
        if (keys.State == EvidenceKeyState.Unavailable) throw new EvidenceKeyUnavailableException("unavailable");
        return keys.State == EvidenceKeyState.Ready && keys.CurrentKeyId is { } id && keys.Key(id) is { } key ? (id, key) : null;
    }

    /// <summary>
    /// The readable content of an open file: decrypted when it's a CBE1 file (throwing
    /// <see cref="EvidenceKeyUnavailableException"/> when its key isn't held), else the file itself from the start.
    /// Takes ownership of <paramref name="file"/>.
    /// </summary>
    public static Stream OpenContent(FileStream file, IEvidenceKeyring keys)
    {
        try
        {
            var head = new byte[Cbe1.HeaderSize];
            var read = file.Read(head);
            if (read == head.Length && Cbe1.IsCbe1(head))
            {
                // Review finding 11: a header that isn't whole names no key; the file is damaged, not plain (never served raw).
                var keyId = Cbe1.KeyIdOf(head) ?? throw new CryptographicException("The encrypted file's header is damaged.");
                return new Cbe1ReadStream(file, keys.Key(keyId) ?? throw new EvidenceKeyUnavailableException(keyId));
            }
            file.Position = 0;
            return file;
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }

    /// <summary>Whether the file at <paramref name="path"/> is encrypted (its first bytes), without opening its content.</summary>
    public static bool IsEncrypted(string path)
    {
        using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        Span<byte> head = stackalloc byte[5];
        return f.Read(head) == head.Length && Cbe1.IsCbe1(head);
    }

    /// <summary>Writes <paramref name="content"/> to <paramref name="file"/>, encrypted when <paramref name="key"/> is given,
    /// and returns the SHA-256 (lower-case hex) and length of the content as it was, not as stored.</summary>
    public static async Task<(string Sha256, long Size)> WriteAsync(FileStream file, Stream content, (string KeyId, byte[] Key)? key,
        CancellationToken ct)
    {
        using var sha = SHA256.Create();
        var encrypted = key is { } k ? new Cbe1WriteStream(file, k.KeyId, k.Key) : null;
        long size;
        await using (var hashing = new CryptoStream(encrypted ?? (Stream)file, sha, CryptoStreamMode.Write, leaveOpen: true))
        {
            await content.CopyToAsync(hashing, ct);
            await hashing.FlushFinalBlockAsync(ct);
        }
        if (encrypted is not null)
        {
            await encrypted.FinishAsync(ct);
            size = encrypted.Length;
            await encrypted.DisposeAsync();
        }
        else size = file.Length;
        await file.FlushAsync(ct);
        file.Flush(flushToDisk: true);
        return (Convert.ToHexString(sha.Hash!).ToLowerInvariant(), size);
    }
}
