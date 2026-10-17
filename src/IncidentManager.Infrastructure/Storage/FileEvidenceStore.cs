using System.Security.Cryptography;
using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Storage;

public sealed class EvidenceStoreOptions
{
    /// <summary>Root directory for the evidence store. Must live OUTSIDE the web root.</summary>
    public string RootPath { get; set; } = "App_Data/evidence-store";
}

/// <summary>
/// Filesystem evidence store. Bytes are written under a randomized name in a per-case folder,
/// hashed (SHA-256) as they stream to disk, and never executed. Reads are path-traversal safe.
/// </summary>
public sealed class FileEvidenceStore : IEvidenceStore
{
    private readonly string _root;

    public FileEvidenceStore(IOptions<EvidenceStoreOptions> options)
    {
        _root = Path.GetFullPath(options.Value.RootPath);
        // PROD-56: a store on a share that's down at start-up mustn't stop the app; the start-up probe reports it.
        try { Directory.CreateDirectory(_root); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* reported by ProbeAsync */ }
    }

    /// <summary>PROD-56: where files arriving in parts are written until they're complete (never a recorded path).</summary>
    private string Incoming => Path.Combine(_root, ".incoming");

    private string IncomingPath(string incoming)
    {
        // A name this store made: hex only, so nothing from a client can point elsewhere.
        if (incoming.Length != 32 || !incoming.All(char.IsAsciiHexDigitLower))
            throw new ArgumentException("Not an upload in progress.", nameof(incoming));
        return Path.Combine(Incoming, incoming + ".part");
    }

    public Task<string> BeginIncomingAsync(CancellationToken ct = default)
    {
        Directory.CreateDirectory(Incoming);
        var name = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        using (new FileStream(IncomingPath(name), FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
        return Task.FromResult(name);
    }

    public async Task AppendIncomingAsync(string incoming, long offset, ReadOnlyMemory<byte> bytes, CancellationToken ct = default)
    {
        await using var fs = new FileStream(IncomingPath(incoming), FileMode.Open, FileAccess.Write, FileShare.None);
        // A part retried after a write that failed half-way starts again where the last whole part ended.
        fs.SetLength(offset);
        fs.Seek(offset, SeekOrigin.Begin);
        await fs.WriteAsync(bytes, ct);
        fs.Flush(flushToDisk: true);
    }

    public Task<Stream> OpenIncomingAsync(string incoming, CancellationToken ct = default) =>
        Task.FromResult<Stream>(new FileStream(IncomingPath(incoming), FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 1 << 16, useAsync: true));

    public Task<StoredEvidence> CommitIncomingAsync(string incoming, Guid caseId, string sha256, long size, CancellationToken ct = default)
    {
        var relDir = caseId.ToString("N");
        Directory.CreateDirectory(Path.Combine(_root, relDir));
        var fileName = Guid.NewGuid().ToString("N") + ".bin";
        File.Move(IncomingPath(incoming), Path.Combine(_root, relDir, fileName), overwrite: false);
        return Task.FromResult(new StoredEvidence($"{relDir}/{fileName}", sha256, size));
    }

    public Task DiscardIncomingAsync(string incoming)
    {
        File.Delete(IncomingPath(incoming));
        return Task.CompletedTask;
    }

    public Task<int> ClearIncomingAsync(TimeSpan olderThan, CancellationToken ct = default)
    {
        if (!Directory.Exists(Incoming)) return Task.FromResult(0);
        var cleared = 0;
        foreach (var f in Directory.EnumerateFiles(Incoming, "*.part"))
        {
            if (DateTime.UtcNow - File.GetLastWriteTimeUtc(f) < olderThan) continue;
            try { File.Delete(f); cleared++; }
            catch (IOException) { /* in use; the next sweep */ }
        }
        return Task.FromResult(cleared);
    }

    public async Task<StoredEvidence> SaveAsync(Guid caseId, Stream content, CancellationToken ct = default)
    {
        var relDir = caseId.ToString("N");
        var absDir = Path.Combine(_root, relDir);
        Directory.CreateDirectory(absDir);

        var fileName = Guid.NewGuid().ToString("N") + ".bin";
        var absPath = Path.Combine(absDir, fileName);

        using var sha = SHA256.Create();
        var created = false;
        try
        {
            await using var fs = new FileStream(absPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            created = true;
            await using var crypto = new CryptoStream(fs, sha, CryptoStreamMode.Write);
            await content.CopyToAsync(crypto, ct);
        }
        catch
        {
            // BUG-206: an upload cut off part-way (the circuit dropped, the disk filled) leaves no partial file behind.
            if (created) File.Delete(absPath);
            throw;
        }

        var size = new FileInfo(absPath).Length;
        var hash = Convert.ToHexString(sha.Hash!).ToLowerInvariant();
        var relPath = $"{relDir}/{fileName}";
        return new StoredEvidence(relPath, hash, size);
    }

    public Task DiscardUnrecordedAsync(string storagePath)
    {
        var abs = Path.GetFullPath(Path.Combine(_root, storagePath));
        var rootPrefix = _root.EndsWith(Path.DirectorySeparatorChar) ? _root : _root + Path.DirectorySeparatorChar;
        if (abs.StartsWith(rootPrefix, StringComparison.Ordinal)) File.Delete(abs);
        return Task.CompletedTask;
    }

    public Task<long?> FreeBytesAsync(CancellationToken ct = default) => StoreVolume.FreeBytesAsync(_root, ct);

    public Task<string?> ProbeAsync(CancellationToken ct = default) => StoreVolume.ProbeAsync(_root, ct);

    public string Location => _root;

    public Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default)
    {
        var abs = Path.GetFullPath(Path.Combine(_root, storagePath));
        // Compare against the root *plus a separator* so a sibling folder sharing the root's name prefix
        // (e.g. "evidence-store-evil" next to "evidence-store") can't pass the containment check (S-07).
        var rootPrefix = _root.EndsWith(Path.DirectorySeparatorChar) ? _root : _root + Path.DirectorySeparatorChar;
        if (!abs.StartsWith(rootPrefix, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Evidence path is outside the store.");

        Stream stream = new FileStream(abs, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Task.FromResult(stream);
    }
}
