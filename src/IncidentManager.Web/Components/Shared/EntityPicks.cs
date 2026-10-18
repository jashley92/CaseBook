using IncidentManager.Domain.Enums;

namespace IncidentManager.Web.Components.Shared;

/// <summary>
/// CAP-02 review (C9): the entities ticked for one verdict, each with the verdict it showed when it was ticked. That
/// is what a bulk verdict is checked against (<c>CaseService.AssessEntitiesAsync</c>'s <c>expected</c>), not the
/// verdicts at the moment the dialog opens: a live refresh between the tick and the dialog reloads the case, so a
/// colleague's Malicious already showed there, the stale check passed, and a Benign overwrote it. Ticking one by one,
/// "select all", "Select Unknown" and the Closure gate's pre-selection all record what was shown.
/// </summary>
public sealed class EntityPicks
{
    private readonly Dictionary<Guid, EntityDisposition> _seen = new();

    public int Count => _seen.Count;

    public bool Contains(Guid id) => _seen.ContainsKey(id);

    /// <summary>Ticks (with the verdict shown now) or unticks one entity. Ticking one already ticked keeps what it showed then.</summary>
    public void Set(Guid id, EntityDisposition shown, bool on)
    {
        if (!on) _seen.Remove(id);
        else _seen.TryAdd(id, shown);
    }

    /// <summary>The selection becomes exactly these entities, each with the verdict shown now.</summary>
    public void Replace(IEnumerable<(Guid Id, EntityDisposition Shown)> entities)
    {
        _seen.Clear();
        foreach (var (id, shown) in entities) _seen.TryAdd(id, shown);
    }

    public void Clear() => _seen.Clear();

    /// <summary>Drops the picks no longer on the case (a colleague removed them); the rest keep what they showed.</summary>
    public void KeepOnly(IEnumerable<Guid> onCase)
    {
        var keep = onCase.ToHashSet();
        foreach (var id in _seen.Keys.Where(id => !keep.Contains(id)).ToList()) _seen.Remove(id);
    }

    /// <summary>
    /// After a refusal the analyst has been told about: each pick now expects the verdict it shows now, so saving again
    /// records theirs knowingly. Picks not in <paramref name="current"/> are left as they were.
    /// </summary>
    public void Rebase(IEnumerable<(Guid Id, EntityDisposition Shown)> current)
    {
        foreach (var (id, shown) in current)
            if (_seen.ContainsKey(id)) _seen[id] = shown;
    }

    /// <summary>A copy of the picks, id to the verdict each showed when ticked: the <c>expected</c> of the save.</summary>
    public Dictionary<Guid, EntityDisposition> Snapshot() => new(_seen);
}
