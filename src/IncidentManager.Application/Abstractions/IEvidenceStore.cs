namespace IncidentManager.Application.Abstractions;

/// <summary>Result of persisting an uploaded evidence file.</summary>
public sealed record StoredEvidence(string StoragePath, string Sha256, long SizeBytes);

/// <summary>
/// Stores evidence bytes outside the web root under a randomized name, computing a SHA-256
/// as the bytes are written. Files are never executed and are streamed back on demand.
/// </summary>
public interface IEvidenceStore
{
    Task<StoredEvidence> SaveAsync(Guid caseId, Stream content, CancellationToken ct = default);

    /// <summary>Opens a read stream for previously stored evidence.</summary>
    Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default);
}
