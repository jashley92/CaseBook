using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Mitre;

/// <summary>
/// One MITRE ATT&amp;CK Enterprise technique (or sub-technique) from the embedded v19.1 catalog —
/// reference data that powers the technique picker so analysts tag canonical IDs, names, and tactics
/// instead of free-typing them. <see cref="Tactics"/> is in ATT&amp;CK matrix order (a technique can
/// belong to several tactics).
/// </summary>
public sealed record AttackTechnique(
    string Id,
    string Name,
    IReadOnlyList<MitreTactic> Tactics,
    bool IsSubtechnique)
{
    /// <summary>The matrix-first tactic (the catalog stores tactics in matrix order), or Unspecified.</summary>
    public MitreTactic PrimaryTactic => Tactics.Count > 0 ? Tactics[0] : MitreTactic.Unspecified;

    /// <summary>Parent technique id for a sub-technique (e.g. <c>T1566.001</c> → <c>T1566</c>); the id itself otherwise.</summary>
    public string ParentId
    {
        get
        {
            var dot = Id.IndexOf('.');
            return dot > 0 ? Id[..dot] : Id;
        }
    }
}
