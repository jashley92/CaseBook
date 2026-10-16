namespace IncidentManager.Application.Common;

/// <summary>
/// C21 (BUG-628, BUG-225's class): orders the reloads of an in-memory copy of stored state. A read is numbered when it
/// starts (<see cref="Begin"/>) and stores what it read through <see cref="TryPublish"/>, which runs only if no read that
/// started later has stored already. Two reloads at once (two saves, a save and a retry) each read, then store; without
/// this the one that read first could store last and put back what a later change removed.
/// </summary>
public sealed class LatestWins
{
    private readonly object _gate = new();
    private long _issued;
    private long _published;

    /// <summary>The number of a read that starts now; later reads get higher ones.</summary>
    public long Begin() => Interlocked.Increment(ref _issued);

    /// <summary>
    /// Runs <paramref name="publish"/> (under this order's lock) unless a read that started after <paramref name="ticket"/>
    /// has published already; whether it ran. The same ticket may publish more than once (callers sharing one read).
    /// </summary>
    public bool TryPublish(long ticket, Action publish)
    {
        lock (_gate)
        {
            if (ticket < _published) return false;
            publish();
            _published = ticket;
            return true;
        }
    }
}

/// <summary>
/// <see cref="LatestWins"/> kept per key (an account): a read for one key is ordered only against reads for the same key.
/// BUG-642: a read can publish a partial answer (some of it didn't come back in time), which mustn't stand in the way of a
/// whole one: an older whole answer still publishes after a newer partial one, but not after a newer whole one.
/// </summary>
public sealed class LatestWinsByKey<TKey> where TKey : notnull
{
    private readonly object _gate = new();
    private readonly Dictionary<TKey, (long Any, long Whole)> _published;
    private long _issued;

    public LatestWinsByKey(IEqualityComparer<TKey>? comparer = null) =>
        _published = new Dictionary<TKey, (long Any, long Whole)>(comparer);

    /// <summary>The number of a read that starts now; later reads (for any key) get higher ones.</summary>
    public long Begin() => Interlocked.Increment(ref _issued);

    /// <summary>
    /// Runs <paramref name="publish"/> (under this order's lock) unless a read for <paramref name="key"/> that started
    /// after <paramref name="ticket"/> has published already (for a <paramref name="partial"/> answer, any such read; for
    /// a whole one, a read that published a whole answer); whether it ran.
    /// </summary>
    public bool TryPublish(TKey key, long ticket, Action publish, bool partial = false)
    {
        lock (_gate)
        {
            _published.TryGetValue(key, out var latest);
            if (ticket < (partial ? latest.Any : latest.Whole)) return false;
            publish();
            _published[key] = (Math.Max(latest.Any, ticket), partial ? latest.Whole : ticket);
            return true;
        }
    }
}
