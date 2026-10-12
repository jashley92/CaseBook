namespace IncidentManager.Application.Notifications;

/// <summary>
/// Remembers which after-action items have already had a <em>due-soon</em> reminder sent (E-03d), so the
/// periodic scan alerts <em>once</em> per item as its due date approaches rather than on every cycle inside
/// the lead window. BUG-95: kept in the database like the overdue tracker's marks, so a restart doesn't resend. Kept separate from <see cref="IOverdueActionItemTracker"/> so the two reminder
/// episodes are independent: an item reminded "due soon" still gets its distinct "overdue" reminder later.
/// The key includes the due date, so an item rescheduled to a new due date is a fresh reminder.
/// </summary>
public interface IDueSoonActionItemTracker
{
    /// <summary>Records the item as notified; returns true only the first time this (item, due-date) is seen.</summary>
    bool TryMarkNotified(Guid actionItemId, DateTimeOffset dueAtUtc);

    /// <summary>BUG-08: un-marks what wasn't delivered, so the next scan sends it again.</summary>
    void Forget(Guid actionItemId, DateTimeOffset dueAtUtc);
}

/// <inheritdoc />
public sealed class DueSoonActionItemTracker(Abstractions.INotificationMarks? marks = null) : IDueSoonActionItemTracker
{
    private readonly Abstractions.INotificationMarks _marks = marks ?? new Abstractions.InMemoryNotificationMarks();

    private static string Key(Guid id, DateTimeOffset due) => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"duesoon|{id:N}|{due.UtcTicks}");

    public bool TryMarkNotified(Guid actionItemId, DateTimeOffset dueAtUtc) => _marks.TryAdd(Key(actionItemId, dueAtUtc));

    public void Forget(Guid actionItemId, DateTimeOffset dueAtUtc) => _marks.Remove(Key(actionItemId, dueAtUtc));
}
