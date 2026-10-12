namespace IncidentManager.Application.Abstractions;

/// <summary>
/// BUG-95: what the scheduled scans have already sent, kept across restarts. The trackers record a mark before they
/// send and remove it when a send wasn't delivered (BUG-08), so the next scan tries again. The database-backed store
/// also stops two app processes (an overlapped IIS recycle, BUG-137) from both sending the same reminder: only the
/// first to record the mark sends. BUG-147: inside a <see cref="NotificationMarkBatch"/> a mark is a claim until the
/// batch confirms it.
/// </summary>
public interface INotificationMarks
{
    /// <summary>Records the mark; true only for the caller that recorded it first.</summary>
    bool TryAdd(string key);

    void Remove(string key);

    /// <summary>Confirms marks claimed inside a batch, once their sends are done.</summary>
    void Confirm(IReadOnlyCollection<string> keys);

    /// <summary>BUG-156: removes every mark whose key starts with <paramref name="prefix"/> (a case's re-armed reminders).</summary>
    void RemovePrefix(string prefix);
}

/// <summary>Marks kept in memory only: what a restart forgets. For tests, and the fallback with no database.</summary>
public sealed class InMemoryNotificationMarks : INotificationMarks
{
    private readonly object _gate = new();
    private readonly HashSet<string> _keys = new(StringComparer.Ordinal);

    public bool TryAdd(string key)
    {
        lock (_gate)
        {
            if (!_keys.Add(key)) return false;
        }
        NotificationMarkBatch.Current?.Claimed(this, key);
        return true;
    }

    public void Remove(string key)
    {
        lock (_gate) _keys.Remove(key);
        NotificationMarkBatch.Current?.Released(this, key);
    }

    public void Confirm(IReadOnlyCollection<string> keys) { }   // nothing outlives the process to confirm

    public void RemovePrefix(string prefix)
    {
        lock (_gate) _keys.RemoveWhere(k => k.StartsWith(prefix, StringComparison.Ordinal));
    }
}
