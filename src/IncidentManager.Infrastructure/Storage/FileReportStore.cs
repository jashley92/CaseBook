using System.Security.Cryptography;
using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Storage;

public sealed class ReportOutputOptions
{
    public string RootPath { get; set; } = "App_Data/report-output";
}

/// <summary>Stores generated report files per-case, hashing the bytes on write.</summary>
public sealed class FileReportStore : IReportStore
{
    private readonly string _root;

    public FileReportStore(IOptions<ReportOutputOptions> options)
    {
        _root = Path.GetFullPath(options.Value.RootPath);
        Directory.CreateDirectory(_root);
    }

    public async Task<StoredReport> SaveAsync(Guid caseId, string fileName, byte[] content, CancellationToken ct = default)
    {
        var relDir = caseId.ToString("N");
        var absDir = Path.Combine(_root, relDir);
        Directory.CreateDirectory(absDir);

        // BUG-16: never overwrite. A stored report is hashed and its row checked against the file, so replacing one
        // would make an earlier version fail verification; a name that's taken gets a suffix instead.
        var safeName = Path.GetFileName(fileName);
        var stem = Path.GetFileNameWithoutExtension(safeName);
        var ext = Path.GetExtension(safeName);
        for (var n = 2; ; n++)
        {
            var path = Path.Combine(absDir, safeName);
            FileStream fs;
            // Only "that name is taken" moves to the next name (BUG-82): a write that fails part-way (a full disk, a
            // cancelled request) removes what it wrote and fails, rather than leaving a partial file under each name.
            try { fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None); }
            catch (IOException) when (File.Exists(path) && n < 1000)
            {
                safeName = $"{stem}-{n}{ext}";
                continue;
            }
            try
            {
                await using (fs) await fs.WriteAsync(content, ct);
            }
            catch
            {
                try { File.Delete(path); } catch (IOException) { /* best effort */ }
                throw;
            }
            break;
        }

        var hash = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
        return new StoredReport($"{relDir}/{safeName}", hash, content.LongLength);
    }

    public Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default)
    {
        var abs = Path.GetFullPath(Path.Combine(_root, storagePath));
        // Root + separator, so a sibling folder sharing the root's name prefix can't pass (S-07).
        var rootPrefix = _root.EndsWith(Path.DirectorySeparatorChar) ? _root : _root + Path.DirectorySeparatorChar;
        if (!abs.StartsWith(rootPrefix, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Report path is outside the store.");

        Stream stream = new FileStream(abs, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Task.FromResult(stream);
    }
}
