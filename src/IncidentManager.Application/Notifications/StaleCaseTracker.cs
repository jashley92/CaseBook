namespace IncidentManager.Application.Notifications;

/// <summary>
/// Remembers which cases have already had a stale-case nudge sent for a given last-activity instant
/// (PROD-38), so the periodic scan nudges <em>once</em> per quiet spell rather than on every cycle while the
/// case stays quiet. BUG-95: kept in the database, outside the tamper-evident chain, so a restart doesn't resend. The key is
/// (case, last-activity instant): the moment anything is recorded on the case its last-activity advances, so
/// the next quiet spell is a fresh episode and will nudge again — the "reset on activity" behavior.
/// </summary>
public interface IStaleCaseTracker
{
    /// <summary>Records the case as nudged for this quiet spell; returns true only the first time this
    /// (case, last-activity) pair is seen.</summary>
    bool TryMarkNotified(Guid caseId, DateTimeOffset lastActivityAtUtc);

    /// <summary>BUG-08: un-marks what wasn't delivered, so the next scan sends it again.</summary>
    void Forget(Guid caseId, DateTimeOffset lastActivityAtUtc);
}

/// <inheritdoc />
public sealed class StaleCaseTracker(Abstractions.INotificationMarks? marks = null) : IStaleCaseTracker
{
    private readonly Abstractions.INotificationMarks _marks = marks ?? new Abstractions.InMemoryNotificationMarks();

    private static string Key(Guid caseId, DateTimeOffset lastActivity) => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"stale|{caseId:N}|{lastActivity.UtcTicks}");

    public bool TryMarkNotified(Guid caseId, DateTimeOffset lastActivityAtUtc) => _marks.TryAdd(Key(caseId, lastActivityAtUtc));

    public void Forget(Guid caseId, DateTimeOffset lastActivityAtUtc) => _marks.Remove(Key(caseId, lastActivityAtUtc));
}
