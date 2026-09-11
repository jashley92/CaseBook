namespace IncidentManager.Application.Notifications;

/// <summary>
/// Remembers which after-action items have already had a <em>due-soon</em> reminder sent (E-03d), so the
/// periodic scan alerts <em>once</em> per item as its due date approaches rather than on every cycle inside
/// the lead window. In-memory (singleton), so a restart may re-send at most one reminder — the same trade as
/// the overdue tracker. Kept separate from <see cref="IOverdueActionItemTracker"/> so the two reminder
/// episodes are independent: an item reminded "due soon" still gets its distinct "overdue" reminder later.
/// The key includes the due date, so an item rescheduled to a new due date is a fresh reminder.
/// </summary>
public interface IDueSoonActionItemTracker
{
    /// <summary>Records the item as notified; returns true only the first time this (item, due-date) is seen.</summary>
    bool TryMarkNotified(Guid actionItemId, DateTimeOffset dueAtUtc);
}

/// <inheritdoc />
public sealed class DueSoonActionItemTracker : IDueSoonActionItemTracker
{
    private readonly object _gate = new();
    private readonly HashSet<(Guid, DateTimeOffset)> _notified = [];

    public bool TryMarkNotified(Guid actionItemId, DateTimeOffset dueAtUtc)
    {
        lock (_gate) return _notified.Add((actionItemId, dueAtUtc));
    }
}
