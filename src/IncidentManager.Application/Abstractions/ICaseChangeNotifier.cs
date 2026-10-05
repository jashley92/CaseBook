namespace IncidentManager.Application.Abstractions;

/// <summary>What happened to one changed row.</summary>
public enum CaseChangeOp { Added, Modified, Deleted }

/// <summary>RD-22: one row a save changed: its entity type's name (e.g. <c>TimelineEntry</c>), its id and what happened.</summary>
public sealed record CaseChangeItem(string Type, Guid Id, CaseChangeOp Op);

/// <summary>
/// RD-22: a committed save's changes to one case, so a viewer can re-read only what changed. An empty
/// <see cref="Items"/> means "something changed" without detail (re-read everything).
/// </summary>
public sealed record CaseChange(Guid CaseId, string ActorId, IReadOnlyList<CaseChangeItem> Items);

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

    /// <summary>RD-22: signals a case's changes with what changed. Subscribers to <see cref="Subscribe"/> get the actor.</summary>
    void Publish(CaseChange change) => Publish(change.CaseId, change.ActorId);

    /// <summary>
    /// Registers a callback invoked whenever the given case changes; the callback receives the acting
    /// user's id. Dispose the returned handle to stop listening (e.g. when the component is torn down).
    /// </summary>
    IDisposable Subscribe(Guid caseId, Func<string, Task> onChanged);

    /// <summary>RD-22: like <see cref="Subscribe"/>, with what changed.</summary>
    IDisposable SubscribeChanges(Guid caseId, Func<CaseChange, Task> onChanged) =>
        Subscribe(caseId, actor => onChanged(new CaseChange(caseId, actor, [])));

    /// <summary>
    /// Registers a callback invoked whenever <em>any</em> case changes (the changed case id and acting
    /// user id are passed). Backs app-wide surfaces such as the activity feed / notification bell.
    /// Dispose to stop listening.
    /// </summary>
    IDisposable SubscribeAll(Func<Guid, string, Task> onAnyChanged);
}
