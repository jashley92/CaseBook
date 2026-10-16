using System.Text.Json;
using IncidentManager.Application.Compliance;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// WF-11: a case reported before CaseBook recorded which jurisdictions were in play gets them now, so a later change to a
/// data element's jurisdictions doesn't reopen or re-judge it. Its notices name them when it has any (it was reported
/// once each was notified); otherwise today's settings are the best record there is. A no-op once every reported case has
/// them. Runs at start-up, as the system. WF-93: an audited change counted as "1 change after closure by system" on every
/// closed reported case; BUG-631: it's in the row hash now, so it's audited as CaseBook's upkeep, which isn't counted.
/// BUG-563: with the data elements the case has (BUG-284); and a kept value written before the elements were recorded gets
/// them too, so wherever what's in play is read, an element added since is told apart from one the case had.
/// BUG-589: a kept value damaged by a code that held ";" before BUG-404 ("NY;CA", "NY;CA;SSN") is repaired first.
/// </summary>
public static class ReportedJurisdictionsBackfill
{
    public static async Task<int> RunAsync(AppDbContext db, CancellationToken ct = default)
    {
        var cases = await db.Cases.AsNoTracking().AsSplitQuery().Include(c => c.DataElements).Include(c => c.JurisdictionNotices)   // S8733
            .Where(c => c.ReportedAtUtc != null && c.ReportedJurisdictions == null)
            .ToListAsync(ct);
        var written = 0;
        foreach (var c in cases)
        {
            IEnumerable<string> codes = c.JurisdictionNotices.Count > 0
                ? c.JurisdictionNotices.SelectMany(n => NotificationDeadlineService.SplitCodes(n.Jurisdiction))   // BUG-428: a legacy "NY;CA" notice
                : await NotificationDeadlineService.JurisdictionsInPlayAsync(db, c.DataElements.Select(d => d.ElementKey), ct);
            var frozen = string.Join(',', codes.Select(j => j.Trim().ToUpperInvariant()).Where(j => j.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(j => j, StringComparer.Ordinal));
            frozen = Case.WithElements(frozen, c.DataElements.Select(d => d.ElementKey)) ?? frozen;
            written += await WriteAsync(db, c.Id, null, frozen, ct);
        }
        return written + await RepairDamagedAsync(db, ct) + await KeepElementsAsync(db, ct);
    }

    /// <summary>
    /// BUG-631: the kept value is in the case's row hash (format 4), so it's written as an audited change, CaseBook's
    /// upkeep (IntegrityUpkeep: not counted as a change after closure, WF-93, or anywhere else), rather than straight to
    /// the column, which left it changeable unseen. Only while it still holds <paramref name="expected"/>, as the
    /// one-statement update did. The case is read with what its hash covers (its data elements).
    /// </summary>
    private static async Task<int> WriteAsync(AppDbContext db, Guid id, string? expected, string value, CancellationToken ct)
    {
        db.ChangeTracker.Clear();
        var row = await db.Cases.Include(x => x.DataElements).FirstOrDefaultAsync(x => x.Id == id, ct);
        if (row is null || !string.Equals(row.ReportedJurisdictions, expected, StringComparison.Ordinal)) return 0;
        row.ReportedJurisdictions = value;
        db.PendingUpkeep = true;
        try
        {
            await db.SaveChangesAsync(ct);
            // BUG-639: a case changed outside CaseBook is put back as read rather than signed off; the check reports it.
            return string.Equals(row.ReportedJurisdictions, value, StringComparison.Ordinal) ? 1 : 0;
        }
        finally
        {
            db.PendingUpkeep = false;
            db.ChangeTracker.Clear();
        }
    }

    // BUG-589: before BUG-404 a code could hold ";", so a codes-only value "NY;CA" read as code NY and element CA, and one
    // written with its elements read "NY;CA;SSN" as code NY and element "CA;SSN". The elements part of a sound value is
    // empty or names a data element; one naming none (no current, retired or case-held key) is damaged. Its last part is
    // the elements when it names one (or is empty), and everything before it is codes; otherwise all of it is codes, and
    // the elements are added below as for any codes-only value.
    private static async Task<int> RepairDamagedAsync(AppDbContext db, CancellationToken ct)
    {
        var cases = await db.Cases.AsNoTracking()
            .Where(c => c.ReportedJurisdictions != null && EF.Functions.Like(c.ReportedJurisdictions, "%;%"))
            .Select(c => new { c.Id, Kept = c.ReportedJurisdictions! })
            .ToListAsync(ct);
        if (cases.Count == 0) return 0;
        var known = await KnownElementKeysAsync(db, ct);
        var written = 0;
        foreach (var c in cases)
        {
            if (Repaired(c.Kept, known) is not { } fixedValue || fixedValue == c.Kept) continue;
            written += await WriteAsync(db, c.Id, c.Kept, fixedValue, ct);
        }
        return written;
    }

    /// <summary>BUG-589: <paramref name="kept"/> as a sound value, or null when it already is one.</summary>
    public static string? Repaired(string kept, IReadOnlySet<string> knownElementKeys)
    {
        var parts = kept.Split(';');
        bool NamesElements(string part) => part.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(knownElementKeys.Contains);
        if (parts.Length == 1) return null;   // codes only: given its elements in KeepElementsAsync
        var last = parts[^1];
        if (parts.Length == 2 && (string.IsNullOrWhiteSpace(last) || NamesElements(last))) return null;

        var elementsKnown = string.IsNullOrWhiteSpace(last) || NamesElements(last);
        var codeParts = elementsKnown ? parts[..^1] : parts;
        var codes = string.Join(',', codeParts.SelectMany(p => p.Split(',')).Select(j => j.Trim().ToUpperInvariant())
            .Where(j => j.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(j => j, StringComparer.Ordinal));
        if (!elementsKnown) return codes;
        var elements = last.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return Case.WithElements(codes, elements) ?? codes;
    }

    // Every data element key there is or was: the catalogue's, those deleted from it (BUG-569: kept in the audit trail),
    // and any a case holds.
    private static async Task<IReadOnlySet<string>> KnownElementKeysAsync(AppDbContext db, CancellationToken ct)
    {
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        keys.UnionWith(await db.DataElements.AsNoTracking().Select(e => e.Key).ToListAsync(ct));
        keys.UnionWith(await db.Cases.AsNoTracking().SelectMany(c => c.DataElements).Select(d => d.ElementKey).Distinct().ToListAsync(ct));
        foreach (var json in await db.AuditLog.AsNoTracking()
                     .Where(a => a.EntityType == nameof(DataElement) && a.Action == AuditAction.Delete && a.BeforeJson != null)
                     .Select(a => a.BeforeJson!).ToListAsync(ct))
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty(nameof(DataElement.Key), out var k)
                    && k.ValueKind == JsonValueKind.String && k.GetString() is { } key)
                    keys.Add(key);
            }
            catch (JsonException) { /* an entry it can't read names no key */ }
        }
        return keys;
    }

    // BUG-563: a kept value holding only the codes (written before BUG-284) gets the elements the case had. Still reported,
    // that's every element it has: each reader took the kept codes alone, so none was told apart as added. Back to
    // unreported, an element bringing a jurisdiction today that isn't kept is the one that reopened it (one it had brought
    // only kept ones), so it stays in play. Too long to hold them, the value is left as it was.
    private static async Task<int> KeepElementsAsync(AppDbContext db, CancellationToken ct)
    {
        var cases = await db.Cases.AsNoTracking().Include(c => c.DataElements)
            .Where(c => c.ReportedJurisdictions != null && !EF.Functions.Like(c.ReportedJurisdictions, "%;%"))
            .ToListAsync(ct);
        if (cases.Count == 0) return 0;
        var live = NotificationDeadlineService.Live(await NotificationDeadlineService.ElementJurisdictionsAsync(db, ct));
        var written = 0;
        foreach (var c in cases)
        {
            var kept = c.ReportedJurisdictions!;
            var codes = Case.KeptJurisdictions(kept) ?? [];
            var had = c.DataElements.Select(d => d.ElementKey)
                .Where(k => c.ReportedAtUtc is not null || live([k]).All(j => codes.Contains(j, StringComparer.OrdinalIgnoreCase)));
            if (Case.WithElements(kept, had) is not { } withElements) continue;
            written += await WriteAsync(db, c.Id, kept, withElements, ct);
        }
        return written;
    }
}
