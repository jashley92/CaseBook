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

    /// <summary>PROD-55: free bytes on the store's volume (a share included), or null when it can't be told in time.</summary>
    Task<long?> FreeBytesAsync(CancellationToken ct = default) => Task.FromResult<long?>(null);

    /// <summary>The size of the store's volume (or share), for Diagnostics' storage graphic; null when it can't be told.</summary>
    Task<long?> TotalBytesAsync(CancellationToken ct = default) => Task.FromResult<long?>(null);

    /// <summary>PROD-56: null when the store can be written and read as the app's account, else why not (in time, so an
    /// unreachable share answers rather than hangs).</summary>
    Task<string?> ProbeAsync(CancellationToken ct = default) => Task.FromResult<string?>(null);

    /// <summary>Where the store is, for messages and Diagnostics.</summary>
    string Location => "";

    // PROD-56: a file that arrives in parts (a large upload). It's written to the store's incoming folder under a name the
    // store makes, part by part at the offset the last whole part ended, then moved into place once complete and checked.
    Task<string> BeginIncomingAsync(CancellationToken ct = default) => throw new NotSupportedException();
    Task AppendIncomingAsync(string incoming, long offset, ReadOnlyMemory<byte> bytes, CancellationToken ct = default) =>
        throw new NotSupportedException();
    Task<Stream> OpenIncomingAsync(string incoming, CancellationToken ct = default) => throw new NotSupportedException();

    /// <summary>PROD-57: ends the parts once all have arrived (an encrypted file's final chunk); safe to repeat.</summary>
    Task FinishIncomingAsync(string incoming, long size, CancellationToken ct = default) => Task.CompletedTask;
    Task<StoredEvidence> CommitIncomingAsync(string incoming, Guid caseId, string sha256, long size, CancellationToken ct = default) =>
        throw new NotSupportedException();
    Task DiscardIncomingAsync(string incoming) => Task.CompletedTask;

    /// <summary>Deletes parts left by uploads abandoned longer ago than <paramref name="olderThan"/>; how many.</summary>
    Task<int> ClearIncomingAsync(TimeSpan olderThan, CancellationToken ct = default) => Task.FromResult(0);
}
