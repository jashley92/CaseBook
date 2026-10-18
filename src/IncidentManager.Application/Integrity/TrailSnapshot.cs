using System.Reflection;
using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Integrity;

/// <summary>
/// C18: a record as its audit trail last describes it: its Create entry's snapshot, then each update's changed fields
/// over it. The upgrade (RowHashUpgrade) records a row's hash only when the row <see cref="Agrees"/> with this, so a row
/// changed in the database before the upgrade isn't signed off: everything its hash covers that the trail recorded must
/// still be as recorded. A value the trail never recorded (a column added after the row was written) can't be checked
/// and is taken as it is.
/// </summary>
public sealed class TrailSnapshot
{
    private readonly Dictionary<string, string> _fields = new(StringComparer.Ordinal);

    /// <summary>Whether the trail holds the record's Create entry (else it knows only the fields updates changed).</summary>
    public bool HasCreate { get; private set; }

    /// <summary>Whether the latest entry is a removal.</summary>
    public bool Deleted { get; private set; }

    /// <summary>Folds in one entry (in sequence order). An entry without a snapshot (a summary line) says nothing here.</summary>
    public void Add(AuditAction action, string? afterJson)
    {
        if (action == AuditAction.Delete) { Deleted = true; return; }
        if (afterJson is null) return;
        Deleted = false;
        try
        {
            using var doc = JsonDocument.Parse(afterJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return;
            if (action == AuditAction.Create) { _fields.Clear(); HasCreate = true; }
            foreach (var p in doc.RootElement.EnumerateObject()) _fields[p.Name] = p.Value.GetRawText();
        }
        catch (JsonException) { /* not a snapshot this reads; the chain check covers the entry itself */ }
    }

    /// <summary>The text the trail last recorded for a field, or null when it recorded none (or recorded null).</summary>
    public string? Text(string field)
    {
        if (!_fields.TryGetValue(field, out var raw)) return null;
        using var doc = JsonDocument.Parse(raw);
        return doc.RootElement.ValueKind == JsonValueKind.String ? doc.RootElement.GetString() : null;
    }

    /// <summary>Whether the trail recorded a value for the field.</summary>
    public bool Has(string field) => _fields.ContainsKey(field);

    /// <summary>The raw JSON the trail last recorded for a field.</summary>
    public bool TryGetRaw(string field, out string raw) => _fields.TryGetValue(field, out raw!);

    /// <summary>
    /// Values written before this release by CaseBook itself, straight to the column (ExecuteUpdate), so the trail can't
    /// vouch for them; the rule says when the row's value is still one those writers could have left. BUG-630: the kept
    /// deadline was only ever filled in, never changed. BUG-631: the kept jurisdictions were filled in, given their
    /// elements (codes unchanged), or repaired from a ";"-damaged value (codes only added).
    /// </summary>
    private static readonly Dictionary<(Type, string), Func<string, object?, bool>> WrittenAroundTheTrail = new()
    {
        [(typeof(JurisdictionNotice), nameof(JurisdictionNotice.DueAtUtc))] = (raw, _) => raw == "null",
        [(typeof(Case), nameof(Case.ReportedJurisdictions))] = (raw, now) =>
        {
            var was = raw == "null" ? null : JsonSerializer.Deserialize<string>(raw);
            if (was is null) return true;
            var before = Case.KeptJurisdictions(was) ?? [];
            var after = Case.KeptJurisdictions(now as string) ?? [];
            var set = after.ToHashSet(StringComparer.OrdinalIgnoreCase);
            return set.SetEquals(before) || (was.Contains(';') && before.All(set.Contains));
        },
    };

    // Fields a snapshot holds that aren't the record's content: its hash, freshness stamps, and an API token's secret
    // (recorded as "(not recorded)", REV-05).
    private static bool Skipped(Type type, string field) =>
        field is nameof(IHashableEntity.RowHash) or nameof(AuditableEntity.ModifiedAtUtc) or nameof(AuditableEntity.ModifiedBy)
        || (type == typeof(ApiToken) && field == nameof(ApiToken.TokenHash));

    private static readonly MethodInfo Clone = typeof(object).GetMethod("MemberwiseClone", BindingFlags.Instance | BindingFlags.NonPublic)!;

    /// <summary>
    /// A copy of <paramref name="row"/> whose value objects are copied too, so a value set on it doesn't change the row's
    /// own (its child collections are shared). BUG-639: the upkeep guard builds a row as it was read from one.
    /// </summary>
    public static IHashableEntity CopyOf(IHashableEntity row)
    {
        var copy = (IHashableEntity)Clone.Invoke(row, null)!;
        foreach (var p in row.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance)
                     .Where(p => p.PropertyType.Namespace == "IncidentManager.Domain.ValueObjects" && p.GetSetMethod(true) is not null))
            if (p.GetValue(row) is { } owned) p.GetSetMethod(true)!.Invoke(copy, [Clone.Invoke(owned, null)]);
        return copy;
    }

    /// <summary>
    /// Whether <paramref name="row"/> agrees with the trail on everything its hash covers: a copy of the row with each
    /// value the trail recorded put back builds the same canonical as the row itself, in the current format.
    /// </summary>
    public bool Agrees(IHashableEntity row)
    {
        var type = row.GetType();
        var copy = CopyOf(row);

        foreach (var (field, raw) in _fields)
        {
            if (Skipped(type, field)) continue;
            var dot = field.IndexOf('.', StringComparison.Ordinal);
            object target = copy;
            var name = field;
            if (dot > 0)
            {
                if (type.GetProperty(field[..dot]) is not { } nav || nav.GetSetMethod(true) is not { } setNav) continue;
                var owned = nav.GetValue(copy);
                if (owned is null)
                {
                    if (raw == "null") continue;   // the trail has it removed too
                    owned = Activator.CreateInstance(nav.PropertyType, nonPublic: true)!;   // removed outside the trail
                    setNav.Invoke(copy, [owned]);
                }
                target = owned;
                name = field[(dot + 1)..];
            }
            if (target.GetType().GetProperty(name, BindingFlags.Public | BindingFlags.Instance) is not { } p
                || p.GetSetMethod(true) is not { } set || p.GetIndexParameters().Length > 0)
                continue;   // a field the record no longer has
            var current = p.GetValue(target);
            if (dot < 0 && WrittenAroundTheTrail.TryGetValue((type, name), out var allowed) && allowed(raw, current)) continue;
            object? recorded;
            try { recorded = JsonSerializer.Deserialize(raw, p.PropertyType); }
            catch (Exception e) when (e is JsonException or NotSupportedException or ArgumentException) { continue; }   // a type changed since: unknown
            if (!Equals(recorded, current)) set.Invoke(target, [recorded]);
        }
        // CAP-07: a value format 5 brought in that the trail never recorded wasn't set by CaseBook, which audits each one.
        if (BroughtInByFormat5.TryGetValue(type, out var later)
            && later.Any(f => !_fields.ContainsKey(f) && type.GetProperty(f)?.GetValue(row) is not null))
            return false;
        return Canonical.InFormat(Canonical.CurrentFormat, copy.BuildCanonicalContent)
               == Canonical.InFormat(Canonical.CurrentFormat, row.BuildCanonicalContent);
    }

    // CAP-07: the stored values format 5 brought in. Their columns are newer than any trail written before them, so the
    // trail can't put them back: a row holding one its trail never recorded doesn't agree. CAP-08 review: every entity
    // with a Canonical.Since(5, ...) part is listed (a guard test checks), or a value planted under an older hash would
    // be signed off by the upgrade.
    internal static readonly IReadOnlyDictionary<Type, string[]> BroughtInByFormat5 = new Dictionary<Type, string[]>
    {
        [typeof(JurisdictionNotice)] = [nameof(JurisdictionNotice.Method), nameof(JurisdictionNotice.Reference),
            nameof(JurisdictionNotice.NotifiedBy), nameof(JurisdictionNotice.EvidenceId)],
        [typeof(Domain.Entities.Evidence)] = [nameof(Domain.Entities.Evidence.CollectedAtUtc), nameof(Domain.Entities.Evidence.CollectedFrom),
            nameof(Domain.Entities.Evidence.CollectedBy),
            // CAP-21: a withdrawal
            nameof(Domain.Entities.Evidence.WithdrawnAtUtc), nameof(Domain.Entities.Evidence.WithdrawnBy),
            nameof(Domain.Entities.Evidence.WithdrawnReason)],
        [typeof(TimelineEntry)] = [nameof(TimelineEntry.HandedToUserId)],   // CAP-20 review: a handoff's recipient
        [typeof(Case)] = [nameof(Case.TeamId)],   // CAP-36: the owning team
    };

    /// <summary>The trail of each of <paramref name="ids"/> of <paramref name="entityType"/>, read in batches.</summary>
    public static async Task<Dictionary<string, TrailSnapshot>> ForAsync(IAppDbContext db, string entityType,
        IReadOnlyCollection<string> ids, CancellationToken ct = default)
    {
        var result = new Dictionary<string, TrailSnapshot>(StringComparer.OrdinalIgnoreCase);
        foreach (var chunk in ids.Chunk(500))
        {
            var entries = await db.AuditLog.AsNoTracking()
                .Where(a => a.EntityType == entityType && a.EntityId != null && chunk.Contains(a.EntityId))
                .OrderBy(a => a.Sequence)
                .Select(a => new { a.EntityId, a.Action, a.AfterJson })
                .ToListAsync(ct);
            foreach (var e in entries)
            {
                if (!result.TryGetValue(e.EntityId!, out var s)) result[e.EntityId!] = s = new TrailSnapshot();
                s.Add(e.Action, e.AfterJson);
            }
        }
        return result;
    }
}
