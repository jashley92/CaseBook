using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>
/// INV-32: how often a case refers to an entity (as a timeline actor or target, or tagged in an entry, a note or the
/// brief), and which Unknown entities are referred to often enough that their disposition probably needs a look.
/// A read-time view; it suggests, never changes, a disposition.
/// </summary>
public static class EntityMentions
{
    /// <summary>References at or above this many make an Unknown entity worth a disposition review.</summary>
    public const int ReviewThreshold = 3;

    public static int Count(Case c, Guid entityId)
    {
        var tag = $"entity:{entityId}";
        var n = c.TimelineEntries.Count(t => t.IsCurrent && (t.ActorEntityId == entityId || t.TargetEntityId == entityId
                                                              || t.Description.Contains(tag, StringComparison.OrdinalIgnoreCase)));
        n += c.Notes.Count(x => x.IsCurrent && x.Body.Contains(tag, StringComparison.OrdinalIgnoreCase));
        var brief = c.Briefs.FirstOrDefault(b => b.IsCurrent);
        if (new[] { c.Summary, brief?.WorkingAssessment, brief?.Known, brief?.OpenQuestions }
                .Any(p => p?.Contains(tag, StringComparison.OrdinalIgnoreCase) == true))
            n++;
        return n;
    }

    /// <summary>Unknown entities referred to at least <see cref="ReviewThreshold"/> times, most-referenced first.</summary>
    public static List<(CaseEntity Entity, int References)> NeedingReview(Case c) =>
        c.Entities.Where(e => e.Disposition == EntityDisposition.Unknown)
            .Select(e => (Entity: e, References: Count(c, e.Id)))
            .Where(x => x.References >= ReviewThreshold)
            .OrderByDescending(x => x.References).ThenBy(x => x.Entity.CreatedAtUtc)
            .ToList();
}
