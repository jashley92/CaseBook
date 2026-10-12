namespace IncidentManager.Application.Abstractions;

/// <summary>
/// BUG-08: tells a scheduled scan whether the reminders it just handed to <see cref="ICaseNotifications"/> were
/// delivered. Notifications never throw (a mail-server problem mustn't break the work that triggered them), so the
/// email layer swallows send errors; inside a watch it also counts them, and the scan forgets what it marked as sent
/// so the next scan tries again. Flows with the async call, so concurrent scans don't see each other's failures.
/// </summary>
public sealed class DeliveryWatch : IDisposable
{
    private static readonly AsyncLocal<DeliveryWatch?> CurrentWatch = new();

    private readonly DeliveryWatch? _outer;
    private int _failures;
    private int _attributed;
    private readonly HashSet<string> _failedKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _unreached = new(StringComparer.OrdinalIgnoreCase);

    private DeliveryWatch(DeliveryWatch? outer) => _outer = outer;

    /// <summary>Starts counting delivery failures for the calls made until the watch is disposed.</summary>
    public static DeliveryWatch Begin()
    {
        var watch = new DeliveryWatch(CurrentWatch.Value);
        CurrentWatch.Value = watch;
        return watch;
    }

    /// <summary>Whether any send failed since the watch began.</summary>
    public bool Failed => Volatile.Read(ref _failures) > 0;

    /// <summary>How many sends failed since the watch began.</summary>
    public int Failures => Volatile.Read(ref _failures);

    /// <summary>
    /// BUG-94: whether the item with this key should be tried again. When the notifier said which items each failed
    /// send carried (<see cref="Attribute"/>), only those; when a failure wasn't attributed, every item, as before. So
    /// one recipient whose mailbox is gone no longer makes every scan resend everyone's reminders.
    /// </summary>
    public bool ShouldRetry(string key)
    {
        lock (_unreached) if (_unreached.Contains(key)) return true;
        if (!Failed) return false;
        lock (_failedKeys) return Volatile.Read(ref _attributed) < Failures || _failedKeys.Contains(key);
    }

    /// <summary>
    /// BUG-156: called by a notifier for items it could send to nobody (no incident commander or owner yet, or none with
    /// an address on file). Not a failure, but the scan tries them again, so someone named later still gets the reminder.
    /// </summary>
    public static void Unreached(IEnumerable<string> keys)
    {
        var list = keys.ToList();
        if (list.Count == 0) return;
        for (var w = CurrentWatch.Value; w is not null; w = w._outer)
            lock (w._unreached) foreach (var k in list) w._unreached.Add(k);
    }

    /// <summary>Called by a notifier after a send it watched failed: the items that send carried.</summary>
    public static void Attribute(IEnumerable<string> keys, int failures)
    {
        var list = keys.ToList();
        for (var w = CurrentWatch.Value; w is not null; w = w._outer)
        {
            lock (w._failedKeys) foreach (var k in list) w._failedKeys.Add(k);
            Interlocked.Add(ref w._attributed, failures);
        }
    }

    /// <summary>Called by a delivery channel when a send fails; does nothing outside a watch.</summary>
    public static void ReportFailure()
    {
        for (var w = CurrentWatch.Value; w is not null; w = w._outer) Interlocked.Increment(ref w._failures);
    }

    public void Dispose() => CurrentWatch.Value = _outer;
}
