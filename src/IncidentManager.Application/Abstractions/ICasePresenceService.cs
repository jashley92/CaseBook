namespace IncidentManager.Application.Abstractions;

/// <summary>A person currently viewing a case (deduplicated per user for display).</summary>
public sealed record CaseViewer(string UserId, string DisplayName);

/// <summary>
/// Tracks who is currently viewing each case so collaborating analysts can see each other's
/// presence live (U-01b). In-memory and process-local — like <see cref="ICaseChangeNotifier"/>,
/// fine for a single on-prem instance; a scaled-out deployment would back it with a SignalR/Redis
/// backplane. Identity is supplied by the caller (the authenticated circuit); the service holds no
/// database or auth dependency.
/// </summary>
public interface ICasePresenceService
{
    /// <summary>
    /// Records that a viewer (identified by <paramref name="circuitId"/> for cleanup) is looking at a
    /// case. Dispose the returned handle to leave (component teardown / navigation away).
    /// </summary>
    IDisposable Join(Guid caseId, string userId, string displayName, string circuitId);

    /// <summary>Distinct viewers currently on the case, ordered by display name.</summary>
    IReadOnlyList<CaseViewer> Viewers(Guid caseId);

    /// <summary>
    /// Registers a callback invoked whenever the case's viewer set changes. Dispose the handle to
    /// stop listening.
    /// </summary>
    IDisposable Subscribe(Guid caseId, Func<Task> onChanged);

    /// <summary>
    /// Removes every registration made from a circuit — the safety net for a browser tab that closes
    /// or crashes without disposing its component gracefully (called from the circuit handler).
    /// </summary>
    void RemoveCircuit(string circuitId);
}
