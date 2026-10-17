using System.Security.Cryptography;
using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Storage;

public sealed class ReportOutputOptions
{
    public string RootPath { get; set; } = "App_Data/report-output";
}

/// <summary>Stores generated report files per-case, hashing the bytes on write. PROD-57: encrypted at rest (CBE1) when the
/// evidence key is ready, with the same key; the hash is always the report's own. Plain reports still read.</summary>
public sealed class FileReportStore : IReportStore
{
    private readonly string _root;
    private readonly IEvidenceKeyring _keys;

    public FileReportStore(IOptions<ReportOutputOptions> options, IEvidenceKeyring? keys = null)
    {
        _keys = keys ?? NoEvidenceKeys.Instance;
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
        var safeName = DiskName(fileName);
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
                await using (fs) await EncryptedFiles.WriteAsync(fs, new MemoryStream(content, writable: false), EncryptedFiles.ForNewFile(_keys), ct);
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

    // BUG-362: the name on disk only. A report is named from its case number, which may hold characters Windows doesn't
    // allow ("|" or "\"" failed every report for the case) or a ":" (written into an NTFS alternate data stream). Each
    // becomes "_", on any host, so a store moved between hosts reads the same; the stem is capped for the 255-character
    // limit, and a Windows device name gets a prefix. The Report row keeps the name as generated, for the download.
    private const int MaxStemLength = 150;
    private static readonly HashSet<char> NotInFileName = [.. Path.GetInvalidFileNameChars(), '<', '>', ':', '"', '/', '\\', '|', '?', '*'];
    private static readonly HashSet<string> DeviceNames = new(StringComparer.OrdinalIgnoreCase)
        { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
          "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };

    internal static string DiskName(string fileName)
    {
        var chars = (fileName ?? "").Select(c => c < 32 || NotInFileName.Contains(c) ? '_' : c).ToArray();
        var name = new string(chars);
        var ext = Path.GetExtension(name);
        var stem = name[..^ext.Length].TrimEnd('.', ' ');   // Windows drops a trailing dot or space
        if (stem.Length > MaxStemLength) stem = stem[..MaxStemLength].TrimEnd('.', ' ');
        if (stem.Length == 0) stem = "report";
        if (DeviceNames.Contains(stem)) stem = "_" + stem;
        return stem + ext;
    }

    public Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default)
    {
        var abs = Path.GetFullPath(Path.Combine(_root, storagePath));
        // Root + separator, so a sibling folder sharing the root's name prefix can't pass (S-07).
        var rootPrefix = _root.EndsWith(Path.DirectorySeparatorChar) ? _root : _root + Path.DirectorySeparatorChar;
        if (!abs.StartsWith(rootPrefix, StringComparison.Ordinal))
            throw new ReportPathOutsideStoreException();

        return Task.FromResult(EncryptedFiles.OpenContent(new FileStream(abs, FileMode.Open, FileAccess.Read, FileShare.Read), _keys));
    }
}
