using IncidentManager.Application.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Evidence;

/// <summary>
/// PROD-55: the administrator's limits on evidence storage (config section <c>Evidence</c>, set in Administration). The
/// largest single file, the most all evidence may take, and the free space an upload must leave on the store's volume.
/// </summary>
public sealed class EvidenceStorageOptions
{
    private const long Mib = 1024L * 1024, Gib = 1024L * Mib;

    /// <summary>The largest single file, in MB.</summary>
    public int MaxUploadMB { get; set; } = 500;

    /// <summary>The most all stored evidence may take, in GB; 0 is no limit.</summary>
    public int StorageQuotaGB { get; set; }

    /// <summary>The free space an upload must leave on the store's volume, in GB.</summary>
    public int MinFreeSpaceGB { get; set; } = 10;

    /// <summary>PROD-55: re-read and verify a large upload before recording it (catches a corrupted write over a share).</summary>
    public bool ReadBackCheck { get; set; } = true;

    /// <summary>PROD-58: when the password-protected zip is a file's main download (RiskyTypes, Always or Off).</summary>
    public string SafeDownload { get; set; } = nameof(SafeDownloadMode.RiskyTypes);

    /// <summary>The safe-download mode in force; a value that isn't one of the names (a number included) reads as the default.</summary>
    public SafeDownloadMode SafeDownloadMode =>
        IncidentManager.Domain.Common.EnumNames.TryParse<SafeDownloadMode>(SafeDownload, out var m, ignoreCase: true) ? m : SafeDownloadMode.RiskyTypes;

    public long MaxUploadBytes => Math.Max(1, (long)MaxUploadMB) * Mib;
    public long? QuotaBytes => StorageQuotaGB > 0 ? StorageQuotaGB * Gib : null;
    public long ReserveBytes => Math.Max(0, (long)MinFreeSpaceGB) * Gib;
}

/// <summary>How much the evidence store holds, against its limits, for Diagnostics and the uploader's warning.</summary>
public sealed record EvidenceStorageUse(long UsedBytes, long? QuotaBytes, long? FreeBytes, long ReserveBytes, long? TotalBytes = null)
{
    /// <summary>The share of the quota used, 0 to 1 (past 1 when over), or null with no quota.</summary>
    public double? QuotaShare => QuotaBytes is { } q and > 0 ? (double)UsedBytes / q : null;

    /// <summary>At or past 90 % of the quota.</summary>
    public bool NearQuota => QuotaBytes is { } q && UsedBytes >= q / 10 * 9;
}

/// <summary>
/// PROD-55: the one check every upload path makes (in-page, chunked, a pasted screenshot) before it stores a byte, and
/// again before it records the file (C2: one function for the start and the end). The quota counts stored evidence, from
/// the records; the free space is the store's volume's, from the store (a UNC share included).
/// </summary>
public static class EvidenceRoom
{
    /// <summary>What evidence takes against the limits; with <paramref name=withVolume/>, the store's volume size too
    /// (for Diagnostics' graphic; an upload's check doesn't need it).</summary>
    public static async Task<EvidenceStorageUse> UseAsync(IAppDbContext db, IEvidenceStore store, EvidenceStorageOptions o,
        bool withVolume = false, CancellationToken ct = default)
    {
        var used = await db.Evidence.AsNoTracking().SumAsync(e => (long?)e.SizeBytes, ct) ?? 0;
        return new EvidenceStorageUse(used, o.QuotaBytes, await store.FreeBytesAsync(ct), o.ReserveBytes,
            withVolume ? await store.TotalBytesAsync(ct) : null);
    }

    /// <summary>Refuses (with a message for the uploader) a file of <paramref name="size"/> bytes that doesn't fit.</summary>
    public static async Task CheckAsync(IAppDbContext db, IEvidenceStore store, EvidenceStorageOptions o, long size,
        CancellationToken ct = default)
    {
        if (size < 0) throw new ArgumentException("That file's size couldn't be read. Try again.");
        if (size > o.MaxUploadBytes)
            throw new ArgumentException($"That file is {Size(size)}; the largest file CaseBook takes is {Size(o.MaxUploadBytes)}. " +
                                        "An administrator can raise the limit (Administration › Governance & security).");
        var use = await UseAsync(db, store, o, ct: ct);
        if (use.QuotaBytes is { } quota && use.UsedBytes > quota - size)
            throw new ArgumentException($"Storing it would take evidence past its {Size(quota)} limit ({Size(use.UsedBytes)} is used). " +
                                        "Ask an administrator to raise the limit.");
        if (use.FreeBytes is { } free && free - size < use.ReserveBytes)
            throw new ArgumentException($"The evidence store doesn't have room for it: storing it would leave less than " +
                                        $"{Size(use.ReserveBytes)} free. Ask an administrator to free space or move the store.");
    }

    /// <summary>A size for people: 812 KB, 4.2 MB, 1.5 GB (invariant, C12).</summary>
    public static string Size(long bytes) => bytes switch
    {
        < 1024 * 1024 => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{Math.Max(1, bytes / 1024.0):0} KB"),
        < 1024L * 1024 * 1024 => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{bytes / (1024.0 * 1024):0.#} MB"),
        _ => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{bytes / (1024.0 * 1024 * 1024):0.#} GB"),
    };
}
