using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;

namespace IncidentManager.Application.Cases;

/// <summary>
/// RD-22: the parts of a case a workspace can re-read on their own when a collaborator changes them. Anything else (the
/// case row, its phase, rung, severity, team, gates, materiality, data elements, links) is <see cref="Whole"/>: the
/// workspace re-reads the case as before.
/// </summary>
[Flags]
public enum CaseRegions
{
    None = 0,
    Record = 1,      // timeline entries and decisions (with their tactics), evidence citations
    Notes = 2,       // working notes
    Tasks = 4,       // tasks and their comments and results
    Things = 8,      // entities, relationships, verdict history, ATT&CK techniques
    Evidence = 16,   // evidence files and citations
    Brief = 32,      // the brief and its versions
    Paper = 64,      // reports, the review, improvement actions
    Whole = 1 << 30,
}

public static class CaseRegionMap
{
    private static readonly Dictionary<string, CaseRegions> ByType = new(StringComparer.Ordinal)
    {
        [nameof(TimelineEntry)] = CaseRegions.Record,
        [nameof(EventStepTactic)] = CaseRegions.Record,
        [nameof(EvidenceCitation)] = CaseRegions.Record | CaseRegions.Evidence,
        [nameof(AnalystNote)] = CaseRegions.Notes,
        [nameof(ActionItem)] = CaseRegions.Tasks,
        [nameof(ActionItemComment)] = CaseRegions.Tasks,
        [nameof(CaseEntity)] = CaseRegions.Things,
        [nameof(EntityRelationship)] = CaseRegions.Things,
        [nameof(EntityVerdictChange)] = CaseRegions.Things,
        [nameof(CaseTechnique)] = CaseRegions.Things,
        [nameof(Domain.Entities.Evidence)] = CaseRegions.Evidence,
        [nameof(CaseBrief)] = CaseRegions.Brief,
        [nameof(Report)] = CaseRegions.Paper,
        [nameof(PostIncidentReview)] = CaseRegions.Paper,
        [nameof(ImprovementAction)] = CaseRegions.Paper,
    };

    /// <summary>The regions a change touches; <see cref="CaseRegions.Whole"/> for a change without detail or with any other kind.</summary>
    public static CaseRegions Of(CaseChange change)
    {
        if (change.Items.Count == 0) return CaseRegions.Whole;
        var r = CaseRegions.None;
        foreach (var i in change.Items)
            r |= ByType.TryGetValue(i.Type, out var region) ? region : CaseRegions.Whole;
        return r;
    }
}
