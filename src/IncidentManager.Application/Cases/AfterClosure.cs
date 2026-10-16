using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
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
    // BUG-321: and a report generated or approved after closure is a document about the record, not a change to it (the
    // final report and the lessons report are expected then).
    private static readonly string[] NotTheCaseRecord = ["ImprovementAction", "PostIncidentReview", "Report"];

    // BUG-321: a case-row update that only picked the report's section layout (saved when a report is generated).
    private static readonly HashSet<string> LayoutOnly = new(StringComparer.Ordinal)
        { nameof(Case.ReportProfileId), nameof(Case.ModifiedAtUtc), nameof(Case.ModifiedBy), nameof(Case.RowHash) };

    private static bool OnlyLayout(string? afterJson)
    {
        if (afterJson is null) return false;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(afterJson);
            return doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object
                && doc.RootElement.EnumerateObject().Any()
                && doc.RootElement.EnumerateObject().All(p => LayoutOnly.Contains(p.Name));
        }
        catch (System.Text.Json.JsonException) { return false; }
    }

    /// <summary>
    /// REV-01/WF-49: every number a case has held, its current one included. An audit entry carries the number at save
    /// time, so entries from before a promotion or renumber are under an older one. (A number once held is never given
    /// to another case, BUG-53/145.)
    /// </summary>
    public static async Task<List<string>> NumbersHeldAsync(IAppDbContext db, Guid caseId, string current, CancellationToken ct = default) =>
        (await NumbersHeldAsync(db, [(caseId, current)], ct)).Keys.ToList();

    /// <summary>As <see cref="NumbersHeldAsync(IAppDbContext, Guid, string, CancellationToken)"/> for several cases: each
    /// number, with the case that held it.</summary>
    public static async Task<Dictionary<string, Guid>> NumbersHeldAsync(IAppDbContext db,
        IReadOnlyCollection<(Guid Id, string Current)> cases, CancellationToken ct = default)
    {
        var result = cases.ToDictionary(c => c.Current, c => c.Id, StringComparer.Ordinal);
        if (cases.Count == 0) return result;
        var ids = cases.Select(c => c.Id.ToString()).ToList();
        var held = await db.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == nameof(Case) && a.EntityId != null && ids.Contains(a.EntityId) && a.CaseNumber != null)
            .Select(a => new { a.EntityId, a.CaseNumber }).Distinct().ToListAsync(ct);
        foreach (var h in held)
            if (Guid.TryParse(h.EntityId, out var id)) result.TryAdd(h.CaseNumber!, id);
        return result;
    }

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
            // BUG-308: the row that wrote it, not a later correction of when it happened (an update of the same row).
            .Where(a => a.EntityType == "StatusChange" && a.EntityId == closeId && a.Action == AuditAction.Create)
            .OrderBy(a => a.Sequence)
            .Select(a => (DateTimeOffset?)a.AtUtc).FirstOrDefaultAsync(ct) ?? close.ChangedAtUtc;
        // WF-49: under every number the case has held (REV-01): an entry carries the number at save time, so renumbering a
        // closed case hid the changes made before it under the old number.
        var numbers = await NumbersHeldAsync(db, caseId, c.CaseNumber, ct);
        var rows = await db.AuditLog.AsNoTracking()
            .Where(a => a.CaseNumber != null && numbers.Contains(a.CaseNumber) && a.AtUtc > closedAt && !NotTheCaseRecord.Contains(a.EntityType)
                        // C18: nor CaseBook's own upkeep (a kept value filled in, a row hash recorded at the upgrade).
                        && a.Reason != Integrity.IntegrityUpkeep.Reason
                        // WF-93: the v1.5.8-v1.6.2 start-up back-fill of the reported jurisdictions wasn't a change to the record.
                        && !(a.Actor == "system" && a.EntityType == nameof(Case) && a.Action == AuditAction.Update
                             && a.AfterJson != null && a.AfterJson.Contains("\"ReportedJurisdictions\"")))
            .Select(a => new { a.AtUtc, a.Actor, Layout = a.EntityType == nameof(Case) && a.Action == AuditAction.Update ? a.AfterJson : null })
            .ToListAsync(ct);
        rows = rows.Where(r => !OnlyLayout(r.Layout)).ToList();
        return new AfterClosureChanges(rows.Select(r => r.AtUtc).Distinct().Count(),
            rows.Select(r => r.Actor).Distinct().ToList(), close.ChangedAtUtc,
            rows.Count == 0 ? null : rows.Max(r => r.AtUtc));
    }
}
