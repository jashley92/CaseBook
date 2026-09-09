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
        Directory.CreateDirectory(_root);
    }

    public async Task<StoredEvidence> SaveAsync(Guid caseId, Stream content, CancellationToken ct = default)
    {
        var relDir = caseId.ToString("N");
        var absDir = Path.Combine(_root, relDir);
        Directory.CreateDirectory(absDir);

        var fileName = Guid.NewGuid().ToString("N") + ".bin";
        var absPath = Path.Combine(absDir, fileName);

        using var sha = SHA256.Create();
        await using (var fs = new FileStream(absPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        await using (var crypto = new CryptoStream(fs, sha, CryptoStreamMode.Write))
        {
            await content.CopyToAsync(crypto, ct);
        }

        var size = new FileInfo(absPath).Length;
        var hash = Convert.ToHexString(sha.Hash!).ToLowerInvariant();
        var relPath = $"{relDir}/{fileName}";
        return new StoredEvidence(relPath, hash, size);
    }

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
