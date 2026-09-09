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

        var safeName = Path.GetFileName(fileName);
        var absPath = Path.Combine(absDir, safeName);
        await File.WriteAllBytesAsync(absPath, content, ct);

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
