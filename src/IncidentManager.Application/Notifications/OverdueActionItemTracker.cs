namespace IncidentManager.Application.Notifications;

/// <summary>
/// Remembers which after-action items have already had an overdue reminder sent this run (E-03b), so the
/// periodic scan alerts <em>once</em> per item rather than on every cycle while it stays overdue. BUG-95: the marks
/// are kept in the database (<see cref="Abstractions.INotificationMarks"/>), outside the tamper-evident audit chain,
/// so a restart doesn't resend them. The key includes the due date, so an item rescheduled to a new due date and gone
/// overdue again is treated as a fresh reminder.
/// </summary>
public interface IOverdueActionItemTracker
{
    /// <summary>Records the item as notified; returns true only the first time this (item, due-date) is seen.</summary>
    bool TryMarkNotified(Guid actionItemId, DateTimeOffset dueAtUtc);

    /// <summary>PROD-03: records an escalation tier as sent; true only the first time for this (item, due date, tier).</summary>
    bool TryMarkEscalated(Guid actionItemId, DateTimeOffset dueAtUtc, int tier);

    /// <summary>BUG-08: un-marks reminders that weren't delivered, so the next scan sends them again.</summary>
    void ForgetNotified(Guid actionItemId, DateTimeOffset dueAtUtc);

    void ForgetEscalated(Guid actionItemId, DateTimeOffset dueAtUtc, int tier);
}

/// <inheritdoc />
public sealed class OverdueActionItemTracker(Abstractions.INotificationMarks? marks = null) : IOverdueActionItemTracker
{
    private readonly Abstractions.INotificationMarks _marks = marks ?? new Abstractions.InMemoryNotificationMarks();

    private static string Notified(Guid id, DateTimeOffset due) => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"overdue|{id:N}|{due.UtcTicks}");
    private static string Escalated(Guid id, DateTimeOffset due, int tier) => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"escalation|{id:N}|{due.UtcTicks}|{tier}");

    public bool TryMarkNotified(Guid actionItemId, DateTimeOffset dueAtUtc) => _marks.TryAdd(Notified(actionItemId, dueAtUtc));

    public bool TryMarkEscalated(Guid actionItemId, DateTimeOffset dueAtUtc, int tier) =>
        _marks.TryAdd(Escalated(actionItemId, dueAtUtc, tier));

    public void ForgetNotified(Guid actionItemId, DateTimeOffset dueAtUtc) => _marks.Remove(Notified(actionItemId, dueAtUtc));

    public void ForgetEscalated(Guid actionItemId, DateTimeOffset dueAtUtc, int tier) =>
        _marks.Remove(Escalated(actionItemId, dueAtUtc, tier));
}
