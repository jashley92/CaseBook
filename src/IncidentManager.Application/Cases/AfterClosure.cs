using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Cases;

/// <summary>HR-15: what has been changed on a closed case since it closed.</summary>
/// <param name="Count">How many saves changed the record (one action can write several audit rows).</param>
/// <param name="People">Who made them (user ids).</param>
/// <param name="ClosedRecordedAtUtc">When the current closure was recorded.</param>
/// <param name="LastAtUtc">The latest change.</param>
public sealed record AfterClosureChanges(int Count, IReadOnlyList<string> People, DateTimeOffset ClosedRecordedAtUtc,
    DateTimeOffset? LastAtUtc);

/// <summary>
/// HR-15: a closed case isn't locked (records are completed after the fact), but what changed after closure is said
/// openly: on the header, on the timeline and in the report. Counted from the audit trail after the save that
/// recorded the latest close. The post-incident review and its improvement actions aren't counted: following them
/// up after closure is expected, and they're a separate record (the lessons report).
/// </summary>
public static class AfterClosure
{
    private static readonly string[] NotTheCaseRecord = ["ImprovementAction", "PostIncidentReview"];

    /// <summary>Null while the case is open. The caller has already checked the user can see the case.</summary>
    public static async Task<AfterClosureChanges?> QueryAsync(IAppDbContext db, Guid caseId, CancellationToken ct = default)
    {
        var c = await db.Cases.AsNoTracking().Where(x => x.Id == caseId)
            .Select(x => new { x.CaseNumber, x.Phase }).FirstOrDefaultAsync(ct);
        if (c is not { Phase: CasePhase.Closed }) return null;
        var close = await db.StatusChanges.AsNoTracking()
            .Where(s => s.CaseId == caseId && s.To == CasePhase.Closed)
            .OrderByDescending(s => s.ChangedAtUtc)
            .Select(s => new { s.Id, s.ChangedAtUtc }).FirstOrDefaultAsync(ct);
        if (close is null) return null;

        // Everything the close itself wrote (the case row, the closing brief, the gate passage) shares its save's time.
        var closeId = close.Id.ToString();
        var closedAt = await db.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == "StatusChange" && a.EntityId == closeId)
            .Select(a => (DateTimeOffset?)a.AtUtc).FirstOrDefaultAsync(ct) ?? close.ChangedAtUtc;
        var rows = await db.AuditLog.AsNoTracking()
            .Where(a => a.CaseNumber == c.CaseNumber && a.AtUtc > closedAt && !NotTheCaseRecord.Contains(a.EntityType))
            .Select(a => new { a.AtUtc, a.Actor })
            .ToListAsync(ct);
        return new AfterClosureChanges(rows.Select(r => r.AtUtc).Distinct().Count(),
            rows.Select(r => r.Actor).Distinct().ToList(), close.ChangedAtUtc,
            rows.Count == 0 ? null : rows.Max(r => r.AtUtc));
    }
}
