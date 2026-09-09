namespace IncidentManager.Application.Abstractions;

public sealed record StoredReport(string StoragePath, string Sha256, long SizeBytes);

/// <summary>Persists generated report files outside the web root and streams them back.</summary>
public interface IReportStore
{
    Task<StoredReport> SaveAsync(Guid caseId, string fileName, byte[] content, CancellationToken ct = default);
    Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default);
}
