using IncidentManager.Application.Sla;

namespace IncidentManager.Application.Notifications;

/// <summary>
/// Remembers which cases have already had a regulatory-deadline reminder sent for a given <em>band</em>
/// (PROD-37), so the periodic scan alerts <em>once</em> as a case crosses into "at risk" and again if it
/// crosses into "breached" — rather than on every cycle while it sits there. In-memory (singleton), so a
/// restart may re-send at most one reminder per band — the same "ops telemetry out of the tamper-evident
/// chain" trade as the overdue/due-soon trackers. The key is (case, band, deadline instant): a case whose
/// clock is re-based (e.g. the materiality decision date is corrected) has a new deadline and so is treated
/// as a fresh reminder.
/// </summary>
public interface IDeadlineReminderTracker
{
    /// <summary>Records the case as reminded for this (band, deadline); returns true only the first time that
    /// combination is seen.</summary>
    bool TryMarkNotified(Guid caseId, SlaState band, DateTimeOffset? dueAtUtc);
}

/// <inheritdoc />
public sealed class DeadlineReminderTracker : IDeadlineReminderTracker
{
    private readonly object _gate = new();
    private readonly HashSet<(Guid, SlaState, DateTimeOffset)> _notified = [];

    public bool TryMarkNotified(Guid caseId, SlaState band, DateTimeOffset? dueAtUtc)
    {
        lock (_gate) return _notified.Add((caseId, band, dueAtUtc ?? DateTimeOffset.MinValue));
    }
}
