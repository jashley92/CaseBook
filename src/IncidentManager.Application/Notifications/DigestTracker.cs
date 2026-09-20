using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Notifications;

/// <summary>
/// Remembers which users have already had a work digest sent for the current period (PROD-39), so the scan
/// sends <em>once</em> per period (one per day for Daily, one per ISO week for Weekly) rather than on every
/// cycle. In-memory (singleton), so a restart may re-send at most one digest — the same "ops telemetry out of
/// the tamper-evident chain" trade as the reminder trackers. The key includes the cadence and the period key,
/// so a user who switches cadence, or the roll into a new day/week, is a fresh send.
/// </summary>
public interface IDigestTracker
{
    /// <summary>Records the digest as sent for this (user, cadence, period); returns true only the first time
    /// that combination is seen.</summary>
    bool TryMarkSent(string userId, DigestCadence cadence, string periodKey);
}

/// <inheritdoc />
public sealed class DigestTracker : IDigestTracker
{
    private readonly object _gate = new();
    private readonly HashSet<(string, DigestCadence, string)> _sent = new();

    public bool TryMarkSent(string userId, DigestCadence cadence, string periodKey)
    {
        lock (_gate) return _sent.Add((userId, cadence, periodKey));
    }
}
