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

    /// <summary>Called by a delivery channel when a send fails; does nothing outside a watch.</summary>
    public static void ReportFailure()
    {
        for (var w = CurrentWatch.Value; w is not null; w = w._outer) Interlocked.Increment(ref w._failures);
    }

    public void Dispose() => CurrentWatch.Value = _outer;
}
