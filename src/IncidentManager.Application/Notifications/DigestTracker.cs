using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Notifications;

/// <summary>
/// Remembers which users have already had a work digest sent for the current period (PROD-39), so the scan
/// sends <em>once</em> per period (one per day for Daily, one per ISO week for Weekly) rather than on every
/// cycle. BUG-95: kept in the database, outside the tamper-evident chain, so a restart doesn't resend. The key includes the cadence and the period key,
/// so a user who switches cadence, or the roll into a new day/week, is a fresh send.
/// </summary>
public interface IDigestTracker
{
    /// <summary>Records the digest as sent for this (user, cadence, period); returns true only the first time
    /// that combination is seen.</summary>
    bool TryMarkSent(string userId, DigestCadence cadence, string periodKey);

    /// <summary>BUG-08: un-marks what wasn't delivered, so the next scan sends it again.</summary>
    void Forget(string userId, DigestCadence cadence, string periodKey);
}

/// <inheritdoc />
public sealed class DigestTracker(Abstractions.INotificationMarks? marks = null) : IDigestTracker
{
    private readonly Abstractions.INotificationMarks _marks = marks ?? new Abstractions.InMemoryNotificationMarks();

    // A user id is at most 200 characters, so the key fits the mark's 450.
    private static string Key(string userId, DigestCadence cadence, string periodKey) => $"digest|{cadence}|{periodKey}|{userId.ToLowerInvariant()}";

    public bool TryMarkSent(string userId, DigestCadence cadence, string periodKey) => _marks.TryAdd(Key(userId, cadence, periodKey));

    public void Forget(string userId, DigestCadence cadence, string periodKey) => _marks.Remove(Key(userId, cadence, periodKey));
}
