namespace IncidentManager.Web.HealthChecks;

/// <summary>
/// CAP-18 review (C10): one read of something slow for every probe that asks while it runs, and its answer kept for
/// <see cref="KeepFor"/> after it lands. The health endpoints are anonymous and a monitor or a load balancer polls them;
/// without this, each request started its own read, so a share that doesn't answer parked a thread per request. A caller
/// still waits only its own time limit (<c>WaitAsync</c>), and a read that's still blocked isn't given another thread.
/// A failed read is kept like an answer, so a share that throws isn't asked on every request either.
/// </summary>
public sealed class SharedRead<T>(TimeSpan keepFor, TimeProvider? time = null)
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly Lock _gate = new();
    private Task<T>? _current;
    private long _landedAt;

    /// <summary>How long an answer is kept after its read ends.</summary>
    public TimeSpan KeepFor { get; } = keepFor;

    /// <summary>The read in flight, or the kept answer while it's fresh, or a new read of <paramref name="read"/>.</summary>
    public Task<T> Get(Func<T> read)
    {
        lock (_gate)
        {
            if (_current is { } current
                && (!current.IsCompleted || _time.GetElapsedTime(Volatile.Read(ref _landedAt)) < KeepFor))
                return current;
            var started = Task.Run(() =>
            {
                try { return read(); }
                finally { Volatile.Write(ref _landedAt, _time.GetTimestamp()); }   // before the task completes
            });
            _current = started;
            return started;
        }
    }
}
