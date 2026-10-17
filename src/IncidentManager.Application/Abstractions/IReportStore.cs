namespace IncidentManager.Application.Abstractions;

public sealed record StoredReport(string StoragePath, string Sha256, long SizeBytes);

/// <summary>Persists generated report files outside the web root and streams them back.</summary>
public interface IReportStore
{
    Task<StoredReport> SaveAsync(Guid caseId, string fileName, byte[] content, CancellationToken ct = default);
    Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default);
}

/// <summary>
/// BUG-657: a report's stored path leads outside the store (its row was edited). Refused like an altered file rather than
/// as an access error; still an <see cref="UnauthorizedAccessException"/> for code that catches that.
/// </summary>
public sealed class ReportPathOutsideStoreException() : UnauthorizedAccessException("Report path is outside the store.");
