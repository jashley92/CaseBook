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
/// PROD-57: when the evidence key is ready, files are written encrypted (CBE1) from the first byte, a large upload's parts
/// included, so a malware sample is never readable on the server's disk; the hash and size are always the original
/// file's. Plain files (from before encryption, or before their conversion) still read.
/// </summary>
public sealed class FileEvidenceStore : IEvidenceStore
{
    private readonly string _root;
    private readonly IEvidenceKeyring _keys;

    public FileEvidenceStore(IOptions<EvidenceStoreOptions> options, IEvidenceKeyring? keys = null)
    {
        _root = Path.GetFullPath(options.Value.RootPath);
        _keys = keys ?? NoEvidenceKeys.Instance;
        // PROD-56: the folder isn't created here. Start-up creates it for a fresh store (CreateIfNew) or marks it as
        // holding evidence (HoldsEvidence); a store that holds evidence and has vanished is never recreated empty.
    }

    private volatile bool _holdsEvidence;

    public void HoldsEvidence() => _holdsEvidence = true;

    public void CreateIfNew()
    {
        if (_holdsEvidence) return;
        // A store on a share that's down at start-up mustn't stop the app; the start-up probe reports it.
        try { Directory.CreateDirectory(_root); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* reported by ProbeAsync */ }
    }

    // Before writing: the folder is there, or (a fresh store) is created; one that held evidence and vanished is refused.
    private void EnsureRoot()
    {
        if (Directory.Exists(_root)) return;
        if (_holdsEvidence) throw new EvidenceStoreUnreachableException(_root);
        Directory.CreateDirectory(_root);
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

    private string StatePath(string incoming) => Path.ChangeExtension(IncomingPath(incoming), ".state.json");

    public async Task SaveIncomingStateAsync(string incoming, string state, CancellationToken ct = default)
    {
        var path = StatePath(incoming);
        await File.WriteAllTextAsync(path + ".new", state, ct);
        File.Move(path + ".new", path, overwrite: true);   // never half a state
    }

    public Task<IReadOnlyList<(string Incoming, string State)>> ReadIncomingStatesAsync(CancellationToken ct = default)
    {
        var found = new List<(string, string)>();
        if (Directory.Exists(Incoming))
            foreach (var path in Directory.EnumerateFiles(Incoming, "*.state.json"))
            {
                var name = Path.GetFileName(path)[..^".state.json".Length];
                if (name.Length != 32 || !name.All(char.IsAsciiHexDigitLower) || !File.Exists(IncomingPath(name))) continue;
                try { found.Add((name, File.ReadAllText(path))); }
                catch (IOException) { /* being written: the next start */ }
            }
        return Task.FromResult<IReadOnlyList<(string Incoming, string State)>>(found);
    }

    private void DeleteState(string incoming)
    {
        var path = StatePath(incoming);
        if (File.Exists(path)) File.Delete(path);
    }

    public async Task<string> BeginIncomingAsync(CancellationToken ct = default)
    {
        EnsureRoot();
        Directory.CreateDirectory(Incoming);
        var name = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        await using var fs = new FileStream(IncomingPath(name), FileMode.CreateNew, FileAccess.Write, FileShare.None);
        // PROD-57: encrypted from the start when the key is ready; the header decides how the parts are written.
        if (EncryptedFiles.ForNewFile(_keys) is { } key) await fs.WriteAsync(Cbe1.NewHeader(key.KeyId, key.Key).Header, ct);
        return name;
    }

    public async Task AppendIncomingAsync(string incoming, long offset, ReadOnlyMemory<byte> bytes, CancellationToken ct = default)
    {
        await using var fs = new FileStream(IncomingPath(incoming), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        if (await IncomingCipherAsync(fs, ct) is not { } cipher)
        {
            // A part retried after a write that failed half-way starts again where the last whole part ended.
            fs.SetLength(offset);
            fs.Seek(offset, SeekOrigin.Begin);
            await fs.WriteAsync(bytes, ct);
            fs.Flush(flushToDisk: true);
            return;
        }
        using var gcm = cipher.Gcm;
        // Parts are whole chunks (8 MB is 128 of them) but the last, so a part starts at a chunk's boundary.
        if (offset % Cbe1.ChunkSize != 0) throw new ArgumentException("A part must start on a chunk boundary.", nameof(offset));
        var index = offset / Cbe1.ChunkSize;
        fs.SetLength(Cbe1.ChunkOffset(index));
        fs.Seek(Cbe1.ChunkOffset(index), SeekOrigin.Begin);
        var sealedChunk = new byte[Cbe1.SealedChunk];
        for (var at = 0; at < bytes.Length; at += Cbe1.ChunkSize, index++)
        {
            var piece = bytes.Span.Slice(at, Math.Min(Cbe1.ChunkSize, bytes.Length - at));
            Cbe1.SealChunk(gcm, cipher.FileId, index, false, piece, sealedChunk);
            await fs.WriteAsync(sealedChunk.AsMemory(0, piece.Length + Cbe1.TagSize), ct);
        }
        fs.Flush(flushToDisk: true);
    }

    // The part file's chunk cipher when it's encrypted (its key named by its header), else null.
    private async Task<(AesGcm Gcm, byte[] FileId)?> IncomingCipherAsync(FileStream fs, CancellationToken ct)
    {
        var head = new byte[Cbe1.HeaderSize];
        fs.Position = 0;
        if (await fs.ReadAtLeastAsync(head, head.Length, throwOnEndOfStream: false, ct) < head.Length || Cbe1.KeyIdOf(head) is not { } keyId)
            return null;
        var (fileKey, fileId) = Cbe1.OpenHeader(head, _keys.Key(keyId) ?? throw new EvidenceKeyUnavailableException(keyId));
        var gcm = new AesGcm(fileKey, Cbe1.TagSize);
        CryptographicOperations.ZeroMemory(fileKey);
        return (gcm, fileId);
    }

    /// <summary>PROD-57: ends an encrypted upload's parts with the final chunk (once), so it reads as whole.</summary>
    public async Task FinishIncomingAsync(string incoming, long size, CancellationToken ct = default)
    {
        await using var fs = new FileStream(IncomingPath(incoming), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        if (await IncomingCipherAsync(fs, ct) is not { } cipher) return;
        using var gcm = cipher.Gcm;
        var chunks = (size + Cbe1.ChunkSize - 1) / Cbe1.ChunkSize;
        var dataEnd = Cbe1.HeaderSize + size + chunks * Cbe1.TagSize;
        if (fs.Length == dataEnd + Cbe1.TagSize) return;   // finished already (a repeated "complete")
        if (fs.Length != dataEnd) throw new InvalidOperationException("The upload's parts don't add up to its size.");
        var tag = new byte[Cbe1.TagSize];
        Cbe1.SealChunk(gcm, cipher.FileId, chunks, true, ReadOnlySpan<byte>.Empty, tag);
        fs.Seek(0, SeekOrigin.End);
        await fs.WriteAsync(tag, ct);
        fs.Flush(flushToDisk: true);
    }

    public Task<Stream> OpenIncomingAsync(string incoming, CancellationToken ct = default) =>
        Task.FromResult(EncryptedFiles.OpenContent(new FileStream(IncomingPath(incoming), FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 1 << 16, useAsync: false), _keys));

    public Task<StoredEvidence> CommitIncomingAsync(string incoming, Guid caseId, string sha256, long size, CancellationToken ct = default)
    {
        var relDir = caseId.ToString("N");
        EnsureRoot();
        Directory.CreateDirectory(Path.Combine(_root, relDir));
        var fileName = Guid.NewGuid().ToString("N") + ".bin";
        File.Move(IncomingPath(incoming), Path.Combine(_root, relDir, fileName), overwrite: false);
        DeleteState(incoming);
        _holdsEvidence = true;
        return Task.FromResult(new StoredEvidence($"{relDir}/{fileName}", sha256, size));
    }

    public Task DiscardIncomingAsync(string incoming)
    {
        File.Delete(IncomingPath(incoming));
        DeleteState(incoming);
        return Task.CompletedTask;
    }

    public Task<int> ClearIncomingAsync(TimeSpan olderThan, IReadOnlyCollection<string>? keep = null, CancellationToken ct = default)
    {
        if (!Directory.Exists(Incoming)) return Task.FromResult(0);
        var cleared = 0;
        foreach (var f in Directory.EnumerateFiles(Incoming, "*.part"))
        {
            var name = Path.GetFileNameWithoutExtension(f);
            if (keep is not null && keep.Contains(name)) continue;   // PROD-59: an upload still held (resumable)
            if (DateTime.UtcNow - File.GetLastWriteTimeUtc(f) < olderThan) continue;
            try
            {
                File.Delete(f);
                cleared++;
                var state = Path.Combine(Incoming, name + ".state.json");
                if (File.Exists(state)) File.Delete(state);
            }
            catch (IOException) { /* in use; the next sweep */ }
        }
        // A state whose parts are gone is nothing to resume.
        foreach (var st in Directory.EnumerateFiles(Incoming, "*.state.json"))
        {
            var name = Path.GetFileName(st)[..^".state.json".Length];
            if (!File.Exists(Path.Combine(Incoming, name + ".part")))
                try { File.Delete(st); } catch (IOException) { /* the next sweep */ }
        }
        return Task.FromResult(cleared);
    }

    public async Task<StoredEvidence> SaveAsync(Guid caseId, Stream content, CancellationToken ct = default)
    {
        var relDir = caseId.ToString("N");
        var absDir = Path.Combine(_root, relDir);
        EnsureRoot();
        Directory.CreateDirectory(absDir);

        var fileName = Guid.NewGuid().ToString("N") + ".bin";
        var absPath = Path.Combine(absDir, fileName);

        var created = false;
        string hash;
        long size;
        try
        {
            await using var fs = new FileStream(absPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            created = true;
            (hash, size) = await EncryptedFiles.WriteAsync(fs, content, EncryptedFiles.ForNewFile(_keys), ct);
        }
        catch
        {
            // BUG-206: an upload cut off part-way (the circuit dropped, the disk filled) leaves no partial file behind.
            if (created) File.Delete(absPath);
            throw;
        }
        _holdsEvidence = true;
        return new StoredEvidence($"{relDir}/{fileName}", hash, size);
    }

    public Task DiscardUnrecordedAsync(string storagePath)
    {
        var abs = Path.GetFullPath(Path.Combine(_root, storagePath));
        var rootPrefix = _root.EndsWith(Path.DirectorySeparatorChar) ? _root : _root + Path.DirectorySeparatorChar;
        if (abs.StartsWith(rootPrefix, StringComparison.Ordinal)) File.Delete(abs);
        return Task.CompletedTask;
    }

    public Task<long?> FreeBytesAsync(CancellationToken ct = default) => StoreVolume.FreeBytesAsync(_root, ct);

    public async Task<long?> TotalBytesAsync(CancellationToken ct = default) => (await StoreVolume.SpaceAsync(_root, ct))?.Total;

    public Task<string?> ProbeAsync(CancellationToken ct = default) => StoreVolume.ProbeAsync(_root, mayCreate: !_holdsEvidence, ct);

    public string Location => _root;

    /// <summary>The absolute path of a stored file, refused if it leads outside the store (S-07).</summary>
    public string PathOf(string storagePath)
    {
        var abs = Path.GetFullPath(Path.Combine(_root, storagePath));
        // Compare against the root *plus a separator* so a sibling folder sharing the root's name prefix
        // (e.g. "evidence-store-evil" next to "evidence-store") can't pass the containment check (S-07).
        var rootPrefix = _root.EndsWith(Path.DirectorySeparatorChar) ? _root : _root + Path.DirectorySeparatorChar;
        if (!abs.StartsWith(rootPrefix, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Evidence path is outside the store.");
        return abs;
    }

    public Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default)
    {
        FileStream file;
        try { file = new FileStream(PathOf(storagePath), FileMode.Open, FileAccess.Read, FileShare.Read); }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException && !Directory.Exists(_root))
        {
            // PROD-56: not this file missing but the whole store (the server answered, so this check is quick).
            throw new EvidenceStoreUnreachableException(_root);
        }
        return Task.FromResult(EncryptedFiles.OpenContent(file, _keys));
    }
}
