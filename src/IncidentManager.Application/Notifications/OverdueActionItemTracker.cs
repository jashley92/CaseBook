namespace IncidentManager.Application.Notifications;

/// <summary>
/// Remembers which after-action items have already had an overdue reminder sent this run (E-03b), so the
/// periodic scan alerts <em>once</em> per item rather than on every cycle while it stays overdue. In-memory
/// (singleton), so a restart may re-send at most one reminder — an acceptable trade for keeping this out of
/// the tamper-evident audit chain (the same principle as the F-16/F-17 monitors). The key includes the due
/// date, so an item rescheduled to a new due date and gone overdue again is treated as a fresh reminder.
/// </summary>
public interface IOverdueActionItemTracker
{
    /// <summary>Records the item as notified; returns true only the first time this (item, due-date) is seen.</summary>
    bool TryMarkNotified(Guid actionItemId, DateTimeOffset dueAtUtc);

    /// <summary>PROD-03: records an escalation tier as sent; true only the first time for this (item, due date, tier).</summary>
    bool TryMarkEscalated(Guid actionItemId, DateTimeOffset dueAtUtc, int tier);
}

/// <inheritdoc />
public sealed class OverdueActionItemTracker : IOverdueActionItemTracker
{
    private readonly object _gate = new();
    private readonly HashSet<(Guid, DateTimeOffset)> _notified = [];
    private readonly HashSet<(Guid, DateTimeOffset, int)> _escalated = [];

    public bool TryMarkNotified(Guid actionItemId, DateTimeOffset dueAtUtc)
    {
        lock (_gate) return _notified.Add((actionItemId, dueAtUtc));
    }

    public bool TryMarkEscalated(Guid actionItemId, DateTimeOffset dueAtUtc, int tier)
    {
        lock (_gate) return _escalated.Add((actionItemId, dueAtUtc, tier));
    }
}
