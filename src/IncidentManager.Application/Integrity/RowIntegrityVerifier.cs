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
    ];

    /// <summary>
    /// Checks every hashable record against its own hash and against the hash the chain last recorded for it.
    /// <paramref name="chain"/> is the full audit log in sequence order (the caller has already verified its links).
    /// </summary>
    public static async Task<RowMismatch?> VerifyAsync(IAppDbContext db, IHashChainService hasher,
        IReadOnlyList<AuditLogEntry> chain, CancellationToken ct = default)
    {
        var recorded = LastRecordedHashes(chain);
        foreach (var table in Tables(db))
        {
            await foreach (var row in table.AsAsyncEnumerable().WithCancellation(ct))
            {
                if (row.RowHash is not { Length: > 0 } stored) continue;   // written before row hashes existed
                var entity = (Entity)row;
                var type = row.GetType().Name;
                recorded.TryGetValue((type, entity.Id.ToString()), out var last);

                if (!string.Equals(hasher.ComputeRowHash(row), stored, StringComparison.OrdinalIgnoreCase))
                    return new RowMismatch(type, entity.Id, last.Sequence,
                        $"{type} {entity.Id} was changed outside CaseBook: its content no longer matches its hash.");
                if (last.Hash is { } chained && !string.Equals(chained, stored, StringComparison.OrdinalIgnoreCase))
                    return new RowMismatch(type, entity.Id, last.Sequence,
                        $"{type} {entity.Id} doesn't match its last recorded change (audit entry {last.Sequence}): it was rewritten outside CaseBook.");
            }
        }
        return null;
    }

    /// <summary>Per record (type, id), the row hash its latest audit entry recorded, and that entry's sequence.</summary>
    private static Dictionary<(string Type, string Id), (string? Hash, long Sequence)> LastRecordedHashes(IReadOnlyList<AuditLogEntry> chain)
    {
        var map = new Dictionary<(string, string), (string?, long)>();
        foreach (var e in chain)
        {
            if (e.EntityId is not { } id || e.AfterJson is not { } after) continue;
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
            map[(e.EntityType, id)] = (hash, e.Sequence);
        }
        return map;
    }
}
