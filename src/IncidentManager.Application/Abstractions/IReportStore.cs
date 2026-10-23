namespace IncidentManager.Application.Abstractions;

/// <param name="Encrypted">BUG-712: whether the file was stored encrypted (CBE1), recorded on its row; null when the
/// store doesn't say.</param>
public sealed record StoredReport(string StoragePath, string Sha256, long SizeBytes, bool? Encrypted = null);

/// <summary>Persists generated report files outside the web root and streams them back.</summary>
public interface IReportStore
{
    Task<StoredReport> SaveAsync(Guid caseId, string fileName, byte[] content, CancellationToken ct = default);
    Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default);

    /// <summary>BUG-712: opens a file as its row records it was stored (null decides from its bytes).</summary>
    Task<Stream> OpenReadAsync(string storagePath, bool? encrypted, CancellationToken ct = default) => OpenReadAsync(storagePath, ct);

    /// <summary>Deletes a report's file (a removed case's purge). Absent already is fine.</summary>
    Task DeleteAsync(string storagePath, CancellationToken ct = default) => throw new NotSupportedException("This report store can't delete files.");
}

/// <summary>
/// BUG-657: a report's stored path leads outside the store (its row was edited). Refused like an altered file rather than
/// as an access error; still an <see cref="UnauthorizedAccessException"/> for code that catches that.
/// </summary>
public sealed class ReportPathOutsideStoreException() : UnauthorizedAccessException("Report path is outside the store.");
