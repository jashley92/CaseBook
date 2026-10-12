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

    /// <summary>BUG-206: removes a file just stored whose record couldn't be saved, so no bytes sit in the store
    /// without a record, custody trail or integrity check. Never for recorded evidence.</summary>
    Task DiscardUnrecordedAsync(string storagePath) => Task.CompletedTask;
}
