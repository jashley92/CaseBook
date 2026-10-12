using IncidentManager.Application.Sla;

namespace IncidentManager.Application.Notifications;

/// <summary>
/// Remembers which cases have already had a regulatory-deadline reminder sent for a given <em>band</em>
/// (PROD-37), so the periodic scan alerts <em>once</em> as a case crosses into "at risk" and again if it
/// crosses into "breached" — rather than on every cycle while it sits there. BUG-95: kept in the database, outside
/// the tamper-evident chain, so a restart doesn't resend. The key is (case, band, deadline instant): a case whose
/// clock is re-based (e.g. the materiality decision date is corrected) has a new deadline and so is treated
/// as a fresh reminder.
/// </summary>
public interface IDeadlineReminderTracker
{
    /// <summary>Records the case as reminded for this (band, deadline); returns true only the first time that
    /// combination is seen.</summary>
    bool TryMarkNotified(Guid caseId, SlaState band, DateTimeOffset? dueAtUtc);

    /// <summary>BUG-08: un-marks what wasn't delivered, so the next scan sends it again.</summary>
    void Forget(Guid caseId, SlaState band, DateTimeOffset? dueAtUtc);

    /// <summary>BUG-156: un-marks every reminder sent for the case, when its clock runs again (a notice was cleared).</summary>
    void ForgetCase(Guid caseId);
}

/// <inheritdoc />
public sealed class DeadlineReminderTracker(Abstractions.INotificationMarks? marks = null) : IDeadlineReminderTracker
{
    private readonly Abstractions.INotificationMarks _marks = marks ?? new Abstractions.InMemoryNotificationMarks();

    private static string Key(Guid caseId, SlaState band, DateTimeOffset? due) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture, $"deadline|{caseId:N}|{band}|{(due ?? DateTimeOffset.MinValue).UtcTicks}");

    public bool TryMarkNotified(Guid caseId, SlaState band, DateTimeOffset? dueAtUtc) => _marks.TryAdd(Key(caseId, band, dueAtUtc));

    public void Forget(Guid caseId, SlaState band, DateTimeOffset? dueAtUtc) => _marks.Remove(Key(caseId, band, dueAtUtc));

    public void ForgetCase(Guid caseId)
    {
        var prefix = string.Create(System.Globalization.CultureInfo.InvariantCulture, $"deadline|{caseId:N}|");
        _marks.RemovePrefix(prefix);
        _marks.RemovePrefix("to|" + prefix);   // and who each was sent to (BUG-148)
    }
}
