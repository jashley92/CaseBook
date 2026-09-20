namespace IncidentManager.Application.Notifications;

/// <summary>
/// Remembers which cases have already had a stale-case nudge sent for a given last-activity instant
/// (PROD-38), so the periodic scan nudges <em>once</em> per quiet spell rather than on every cycle while the
/// case stays quiet. In-memory (singleton), so a restart may re-send at most one nudge — the same "ops
/// telemetry out of the tamper-evident chain" trade as the overdue/due-soon/deadline trackers. The key is
/// (case, last-activity instant): the moment anything is recorded on the case its last-activity advances, so
/// the next quiet spell is a fresh episode and will nudge again — the "reset on activity" behavior.
/// </summary>
public interface IStaleCaseTracker
{
    /// <summary>Records the case as nudged for this quiet spell; returns true only the first time this
    /// (case, last-activity) pair is seen.</summary>
    bool TryMarkNotified(Guid caseId, DateTimeOffset lastActivityAtUtc);
}

/// <inheritdoc />
public sealed class StaleCaseTracker : IStaleCaseTracker
{
    private readonly object _gate = new();
    private readonly HashSet<(Guid, DateTimeOffset)> _notified = [];

    public bool TryMarkNotified(Guid caseId, DateTimeOffset lastActivityAtUtc)
    {
        lock (_gate) return _notified.Add((caseId, lastActivityAtUtc));
    }
}
