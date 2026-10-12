using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Integrity;

/// <summary>
/// BUG-06: checks the records themselves, not only the audit chain. Every hashable row carries a hash of its content,
/// and every audited write records that hash in the chain. A row passes when its content still produces its stored
/// hash (catches an edit made directly in the database) and that hash is the one the chain last recorded for it
/// (catches an edit whose author also recomputed the row hash, since the chain is linked and can be keyed and sealed).
/// Rows from before row hashes existed, and rows whose chain entries predate them, are skipped rather than flagged.
/// BUG-64/65: a row whose hash was cleared while the chain holds one, a row the chain last recorded as deleted, a hashed
/// row the chain never recorded, and a row the chain recorded that is no longer there are all flagged too.
/// </summary>
public static class RowIntegrityVerifier
{
    /// <summary>The first record that fails, or null when every checked record matches.</summary>
    public sealed record RowMismatch(string EntityType, Guid Id, long? LastSequence, string Detail);

    /// <summary>The hashable tables checked, each loaded with what its hash covers (a case's data elements, a step's tactics).</summary>
    public static IEnumerable<IQueryable<IHashableEntity>> Tables(IAppDbContext db) =>
    [
        db.Cases.AsNoTracking().Include(c => c.DataElements),
        db.TimelineEntries.AsNoTracking().Include(t => t.Tactics),
        db.Notes.AsNoTracking(),
        db.Evidence.AsNoTracking(),
        db.ActionItems.AsNoTracking(),
        db.ActionItemComments.AsNoTracking(),
        db.CaseEntities.AsNoTracking(),
        db.EntityRelationships.AsNoTracking(),
        db.CaseTechniques.AsNoTracking(),
        db.CaseLinks.AsNoTracking(),
        db.CaseBriefs.AsNoTracking(),
        db.CaseOutcomes.AsNoTracking(),
        db.PostIncidentReviews.AsNoTracking(),
        db.ImprovementActions.AsNoTracking(),
        db.TransitionTimeCorrections.AsNoTracking(),
        db.JurisdictionNotices.AsNoTracking(),
        db.CaseTemplates.AsNoTracking(),
        db.CaseTemplateSteps.AsNoTracking(),
        db.StageGates.AsNoTracking(),
        db.StageGateRequirements.AsNoTracking(),
        db.GatePassages.AsNoTracking(),
        db.ReportProfiles.AsNoTracking(),
        db.ReportTemplates.AsNoTracking(),
        db.DataElements.AsNoTracking(),
        db.NotificationRules.AsNoTracking(),
        db.AppSettings.AsNoTracking(),
        db.Roles.AsNoTracking(),
        db.RoleMappings.AsNoTracking(),
        // BUG-70: when things happened and who could see a case, which were outside the check before.
        db.ClassificationChanges.AsNoTracking(),
        db.StatusChanges.AsNoTracking(),
        db.MaterialityChanges.AsNoTracking(),
        db.SeverityChanges.AsNoTracking(),
        db.AssignmentChanges.AsNoTracking(),
        db.EntityVerdictChanges.AsNoTracking(),
        db.Assignments.AsNoTracking(),
        db.EvidenceCitations.AsNoTracking(),
    ];

    /// <summary>
    /// Checks every hashable record against its own hash and against the hash the chain last recorded for it.
    /// <paramref name="chain"/> is the full audit log in sequence order (the caller has already verified its links).
    /// </summary>
    public static async Task<RowMismatch?> VerifyAsync(IAppDbContext db, IHashChainService hasher,
        IReadOnlyList<AuditLogEntry> chain, CancellationToken ct = default)
    {
        var recorded = LastRecordedHashes(chain);
        var checkedTypes = new HashSet<string>(StringComparer.Ordinal);
        var present = new HashSet<(string, string)>();
        foreach (var table in Tables(db))
        {
            checkedTypes.Add(table.ElementType.Name);
            await foreach (var row in table.AsAsyncEnumerable().WithCancellation(ct))
            {
                var entity = (Entity)row;
                var type = row.GetType().Name;
                var key = (type, entity.Id.ToString());
                present.Add(key);
                var known = recorded.TryGetValue(key, out var last);

                if (known && last.Deleted)
                    return new RowMismatch(type, entity.Id, last.Sequence,
                        $"{type} {entity.Id} was removed (audit entry {last.Sequence}) and put back outside CaseBook.");
                if (row.RowHash is not { Length: > 0 } stored)
                {
                    // BUG-70: in the tables made hashable later, a row the trail records was given its hash at upgrade; one
                    // without a hash that the trail never recorded was added outside CaseBook (an assignment, say).
                    if (!known && HashedFromUpgrade.Contains(type))
                        return new RowMismatch(type, entity.Id, null,
                            $"{type} {entity.Id} isn't in the audit trail: it was added outside CaseBook.");
                    if (last.Hash is not null && !HashClearedByMigration.Contains(type))
                        return new RowMismatch(type, entity.Id, last.Sequence,
                            $"{type} {entity.Id} had its hash removed outside CaseBook (audit entry {last.Sequence} recorded one).");
                    continue;   // written before row hashes existed
                }
                if (!known)
                    return new RowMismatch(type, entity.Id, null,
                        $"{type} {entity.Id} isn't in the audit trail: it was added outside CaseBook.");

                if (!hasher.RowHashMatches(row, stored))   // BUG-24: in the format the hash was written in
                    return new RowMismatch(type, entity.Id, last.Sequence,
                        $"{type} {entity.Id} was changed outside CaseBook: its content no longer matches its hash.");
                if (last.Hash is { } chained && !string.Equals(chained, stored, StringComparison.OrdinalIgnoreCase))
                    return new RowMismatch(type, entity.Id, last.Sequence,
                        $"{type} {entity.Id} doesn't match its last recorded change (audit entry {last.Sequence}): it was rewritten outside CaseBook.");
            }
        }

        // A record the chain last recorded as created or changed (with a row hash, so after row hashes existed) that is
        // no longer in its table was deleted outside CaseBook: the app records every removal.
        foreach (var ((type, id), last) in recorded)
        {
            if (last.Deleted || last.Hash is null || !checkedTypes.Contains(type) || present.Contains((type, id))) continue;
            return new RowMismatch(type, Guid.TryParse(id, out var g) ? g : Guid.Empty, last.Sequence,
                $"{type} {id} is missing: the audit trail records it (entry {last.Sequence}) but it was deleted outside CaseBook.");
        }
        return null;
    }

    /// <summary>
    /// Types a released migration rewrote and cleared the row hash of (ClosureGateHonestChecks, on stage-gate
    /// requirements), so a cleared hash there isn't a sign of tampering. A migration that clears row hashes must add its
    /// type here.
    /// </summary>
    private static readonly HashSet<string> HashClearedByMigration = new(StringComparer.Ordinal) { nameof(StageGateRequirement) };

    /// <summary>
    /// BUG-70: tables made hashable after release, whose existing rows the startup back-fill (RowHashBackfill) gives a
    /// hash when the trail records them. Every row in them is in the trail, so one with neither is flagged.
    /// </summary>
    private static readonly HashSet<string> HashedFromUpgrade = new(StringComparer.Ordinal)
    {
        nameof(ClassificationChange), nameof(StatusChange), nameof(MaterialityChange), nameof(SeverityChange),
        nameof(AssignmentChange), nameof(EntityVerdictChange), nameof(CaseAssignment), nameof(EvidenceCitation),
    };

    /// <summary>Per record (type, id), the row hash its latest audit entry recorded, that entry's sequence, and whether
    /// it was a removal.</summary>
    private static Dictionary<(string Type, string Id), (string? Hash, long Sequence, bool Deleted)> LastRecordedHashes(IReadOnlyList<AuditLogEntry> chain)
    {
        var map = new Dictionary<(string, string), (string?, long, bool)>();
        foreach (var e in chain)
        {
            if (e.EntityId is not { } id) continue;
            if (e.Action == Domain.Enums.AuditAction.Delete) { map[(e.EntityType, id)] = (null, e.Sequence, true); continue; }
            if (e.AfterJson is not { } after) continue;
            // The latest entry decides. Entries written before every update recorded the row hash don't carry it, and
            // a record whose latest entry is one of those is checked against its own hash only.
            string? hash = null;
            if (after.Contains("\"RowHash\"", StringComparison.Ordinal))
            {
                try
                {
                    using var doc = JsonDocument.Parse(after);
                    if (doc.RootElement.TryGetProperty("RowHash", out var h) && h.ValueKind == JsonValueKind.String) hash = h.GetString();
                }
                catch (JsonException) { /* not a snapshot this check reads; the chain check covers the entry itself */ }
            }
            map[(e.EntityType, id)] = (hash, e.Sequence, false);
        }
        return map;
    }
}
