namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Broadcasts "this case changed" events so collaborating analysts see each other's edits live,
/// without a manual refresh. In-memory and process-local — fine for a single on-prem instance; a
/// scaled-out deployment would back this with a SignalR/Redis backplane.
/// </summary>
public interface ICaseChangeNotifier
{
    /// <summary>
    /// Signals that the given case was modified by <paramref name="actorId"/> (the acting user's id).
    /// Safe to call from any thread. Subscribers use the actor to attribute the change (U-30).
    /// </summary>
    void Publish(Guid caseId, string actorId);

    /// <summary>
    /// Registers a callback invoked whenever the given case changes; the callback receives the acting
    /// user's id. Dispose the returned handle to stop listening (e.g. when the component is torn down).
    /// </summary>
    IDisposable Subscribe(Guid caseId, Func<string, Task> onChanged);

    /// <summary>
    /// Registers a callback invoked whenever <em>any</em> case changes (the changed case id and acting
    /// user id are passed). Backs app-wide surfaces such as the activity feed / notification bell.
    /// Dispose to stop listening.
    /// </summary>
    IDisposable SubscribeAll(Func<Guid, string, Task> onAnyChanged);
}
