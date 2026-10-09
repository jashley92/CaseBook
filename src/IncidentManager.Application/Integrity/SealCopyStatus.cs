namespace IncidentManager.Application.Integrity;

/// <summary>
/// Where each new seal's copies went, and how the last attempt at each fared (F-26/F-27), for Diagnostics and the
/// Integrity page. In memory: it describes this process since it started. Thread-safe.
/// </summary>
public sealed class SealCopyStatus
{
    private readonly Dictionary<string, SealCopyResult> _last = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();

    public void Record(string destination, DateTimeOffset atUtc, string? error)
    {
        lock (_gate)
        {
            var previous = _last.GetValueOrDefault(destination);
            _last[destination] = new SealCopyResult(destination, atUtc, error,
                error is null ? atUtc : previous?.LastSuccessUtc);
        }
    }

    public IReadOnlyList<SealCopyResult> Snapshot()
    {
        lock (_gate) return _last.Values.OrderBy(r => r.Destination, StringComparer.Ordinal).ToList();
    }
}

/// <summary>The last copy of a seal to one destination: when it was attempted, its error if it failed, and when one last
/// succeeded.</summary>
public sealed record SealCopyResult(string Destination, DateTimeOffset LastAttemptUtc, string? LastError, DateTimeOffset? LastSuccessUtc)
{
    public bool Ok => LastError is null;
}
