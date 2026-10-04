using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Mitre;

/// <summary>
/// HR-13: one technique on a case, under one tactic: tagged by hand, recorded on attack-chain steps, or both.
/// </summary>
/// <param name="TagId">The manual tag, when there is one (it can be removed; a chain step can't be from here).</param>
/// <param name="ChainSteps">How many attack-chain steps record this technique under this tactic.</param>
public sealed record CaseTechniqueRow(string TechniqueId, string Name, MitreTactic Tactic, Guid? TagId, int ChainSteps)
{
    public bool IsTagged => TagId is not null;
    public bool FromChain => ChainSteps > 0;
}

public static class CaseTechniques
{
    /// <summary>
    /// HR-13: the case's techniques as a reader expects them: the manual tags plus every technique recorded on an
    /// attack-chain step (one row per technique and tactic), so a two-step chain doesn't sit beside "No techniques
    /// tagged". A third-party case's event steps are disclosure milestones, not an attack chain, so they add nothing.
    /// </summary>
    public static IReadOnlyList<CaseTechniqueRow> For(Case c)
    {
        var rows = new Dictionary<(string, MitreTactic), CaseTechniqueRow>();
        foreach (var t in c.Techniques)
            rows[(t.TechniqueId.ToUpperInvariant(), t.Tactic)] = new(t.TechniqueId, t.Name, t.Tactic, t.Id, 0);

        if (c.Origin != CaseOrigin.ThirdParty)
            foreach (var step in c.TimelineEntries.Where(e => e.Kind == TimelineKind.Event && !string.IsNullOrWhiteSpace(e.TechniqueId)))
            {
                var id = step.TechniqueId!.Trim().ToUpperInvariant();
                var tactics = step.Tactics.Select(x => x.Tactic).Where(x => x != MitreTactic.Unspecified).Distinct().ToList();
                if (tactics.Count == 0) tactics.Add(MitreTactic.Unspecified);
                foreach (var tactic in tactics)
                {
                    // A step's technique tagged by hand under no particular tactic is the same technique: merge it.
                    var key = rows.ContainsKey((id, tactic)) ? (id, tactic)
                        : tactic == MitreTactic.Unspecified && rows.Keys.FirstOrDefault(k => k.Item1 == id) is { Item1: not null } any ? any
                        : (id, tactic);
                    rows[key] = rows.TryGetValue(key, out var row)
                        ? row with { ChainSteps = row.ChainSteps + 1 }
                        : new(id, AttackCatalog.Find(id)?.Name ?? "", tactic, null, 1);
                }
            }

        return rows.Values.OrderBy(r => r.Tactic).ThenBy(r => r.TechniqueId, StringComparer.Ordinal).ToList();
    }
}
