namespace IncidentManager.Application.Abstractions;

/// <summary>
/// BUG-147: a scan's sent marks are claims until the scan finishes. A mark recorded inside a batch is kept only when the
/// batch is <see cref="Complete"/>d after the sends; if the scan throws first (a cancelled send during shutdown, a
/// branding file that can't be read) the batch removes what it claimed, so the next scan sends those reminders. The
/// database store also writes a claim as unconfirmed, so one left by a process that stopped mid-send (a crash, a
/// reboot) is cleared at the next start instead of blocking that reminder for good. Flows with the async call, like
/// <see cref="DeliveryWatch"/>, so concurrent scans keep their own claims.
/// </summary>
public sealed class NotificationMarkBatch : IDisposable
{
    private static readonly AsyncLocal<NotificationMarkBatch?> CurrentBatch = new();

    private readonly NotificationMarkBatch? _outer;
    private readonly List<(INotificationMarks Store, string Key)> _claimed = [];
    private bool _completed;
    private bool _disposed;

    private NotificationMarkBatch(NotificationMarkBatch? outer) => _outer = outer;

    /// <summary>Starts a batch: marks recorded until it ends are kept only if it's completed.</summary>
    public static NotificationMarkBatch Begin()
    {
        var batch = new NotificationMarkBatch(CurrentBatch.Value);
        CurrentBatch.Value = batch;
        return batch;
    }

    /// <summary>The batch the calling scan is in, if any.</summary>
    public static NotificationMarkBatch? Current => CurrentBatch.Value;

    /// <summary>Called by a store when it records a mark inside this batch.</summary>
    public void Claimed(INotificationMarks store, string key)
    {
        lock (_claimed) _claimed.Add((store, key));
    }

    /// <summary>Called by a store when a mark is removed (a send that wasn't delivered), so it isn't confirmed.</summary>
    public void Released(INotificationMarks store, string key)
    {
        lock (_claimed) _claimed.RemoveAll(c => ReferenceEquals(c.Store, store) && c.Key == key);
    }

    /// <summary>The sends are done: keep the marks still claimed.</summary>
    public void Complete()
    {
        if (_completed) return;
        _completed = true;
        foreach (var group in Snapshot().GroupBy(c => c.Store))
            group.Key.Confirm(group.Select(c => c.Key).ToList());
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CurrentBatch.Value = _outer;
        if (_completed) return;
        foreach (var (store, key) in Snapshot()) store.Remove(key);
    }

    private List<(INotificationMarks Store, string Key)> Snapshot()
    {
        lock (_claimed) return _claimed.ToList();
    }
}
