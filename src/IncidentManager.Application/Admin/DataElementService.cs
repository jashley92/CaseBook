using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>A data-element reference row for the admin editor / impact picker (X-03). <see cref="IsReferenced"/>
/// is true when at least one case already records this element — such elements can be archived but not deleted.</summary>
public sealed record DataElementView(
    Guid Id, string Key, string Label, int SortOrder, bool IsActive, bool IsSystem,
    string? NotificationJurisdictions, bool IsReferenced)
{
    /// <summary>Hard-delete is allowed only for a non-built-in element that no case references; everything else
    /// is archived instead, so nothing a case points at ever disappears.</summary>
    public bool IsDeletable => !IsSystem && !IsReferenced;
}

/// <summary>One active row submitted by the admin editor: an existing element (Id set) or a new one (Id null).
/// List position is the desired display order; label and notification jurisdictions are the edits. Archiving,
/// restoring and deleting are separate explicit actions, not part of this batch.</summary>
public sealed record DataElementRow(Guid? Id, string Label, string? NotificationJurisdictions);

/// <summary>
/// Administers the data-element reference set (X-03): the personal-data categories the impact assessment
/// offers. Admins may add, relabel, reorder, <b>archive/restore</b>, and (for genuine mistakes) delete
/// elements; each change is audited and hash-chained by the save interceptor like other reference data.
/// The element's stable <b>Key</b> is its identity — the value a case stores and the tamper-evident canonical
/// hashes — so it is generated once and never changed. Two invariants protect that canonical: a referenced
/// element is <b>never hard-deleted</b> (it is archived, keeping it resolvable for the cases that point at it),
/// and built-in elements are never deleted either — archiving is the "remove" for both.
/// </summary>
public sealed class DataElementService
{
    private const int MaxLabelLength = 200;

    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public DataElementService(IAppDbContextFactory factory, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
    }

    /// <summary>Every element, active and archived, in display order — for administration. Each row carries
    /// whether any case references it, so the UI can offer delete only where it is safe.</summary>
    public async Task<List<DataElementView>> ListAllAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var elements = await Ordered(db).ToListAsync(ct);
        var referenced = await db.CaseDataElements.AsNoTracking()
            .Select(c => c.ElementKey).Distinct().ToListAsync(ct);
        var refSet = referenced.ToHashSet(StringComparer.Ordinal);
        return elements.Select(e => Project(e, refSet.Contains(e.Key))).ToList();
    }

    /// <summary>Active elements in display order — the options the impact assessment offers.</summary>
    public async Task<List<DataElementView>> ListActiveAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var elements = await Ordered(db).Where(e => e.IsActive).ToListAsync(ct);
        return elements.Select(e => Project(e, false)).ToList();
    }

    /// <summary>
    /// Applies the editor's <b>active</b> rows in one audited unit: existing rows are relabelled and reordered
    /// to match the submitted order; rows with no id are created (active) with a fresh generated key. Archived
    /// elements are untouched (they are not in the submission). Labels must be present, ≤200 chars, and unique.
    /// </summary>
    public async Task SaveAsync(IReadOnlyList<DataElementRow> rows, CancellationToken ct = default)
    {
        var labels = new List<string>(rows.Count);
        foreach (var r in rows)
        {
            var label = (r.Label ?? "").Trim();
            if (string.IsNullOrWhiteSpace(label))
                throw new ArgumentException("Every data element needs a label.");
            if (label.Length > MaxLabelLength)
                throw new ArgumentException($"A label must be {MaxLabelLength} characters or fewer.");
            labels.Add(label);
        }
        if (labels.Select(l => l.ToLowerInvariant()).Distinct().Count() != labels.Count)
            throw new InvalidOperationException("Data-element labels must be unique.");

        using var db = _factory.CreateDbContext();
        var existing = await db.DataElements.ToListAsync(ct);
        var byId = existing.ToDictionary(e => e.Id);
        var now = _clock.UtcNow;
        var usedKeys = existing.Select(e => e.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < rows.Count; i++)
        {
            var row = rows[i];
            var label = labels[i];
            var order = i + 1;
            var juris = Normalize(row.NotificationJurisdictions);

            if (row.Id is { } id)
            {
                if (!byId.TryGetValue(id, out var el))
                    throw new InvalidOperationException("A data element being edited no longer exists.");
                el.Label = label;
                el.IsActive = true;   // the editor only ever submits the active set
                el.SortOrder = order;
                el.NotificationJurisdictions = juris;
                el.ModifiedBy = _user.UserId;
                el.ModifiedAtUtc = now;
            }
            else
            {
                var key = UniqueKey(label, usedKeys);
                usedKeys.Add(key);
                db.DataElements.Add(new DataElement
                {
                    Key = key,
                    Label = label,
                    SortOrder = order,
                    IsActive = true,
                    IsSystem = false,
                    NotificationJurisdictions = juris,
                    CreatedBy = _user.UserId,
                    CreatedAtUtc = now
                });
            }
        }

        await db.SaveChangesAsync(ct);
    }

    /// <summary>Archives (<paramref name="archived"/> = true) or restores an element — built-in ones included.
    /// Archiving drops it from the impact picker but keeps it on any case that already recorded it. Audited.</summary>
    public async Task SetArchivedAsync(Guid id, bool archived, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var el = await db.DataElements.FirstOrDefaultAsync(e => e.Id == id, ct)
            ?? throw new InvalidOperationException("Data element not found.");
        if (el.IsActive != archived) return; // already in the target state
        el.IsActive = !archived;
        el.ModifiedBy = _user.UserId;
        el.ModifiedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Permanently deletes an element — allowed only when it is <b>not built-in</b> and <b>no case references
    /// it</b>, so the tamper-evident canonical never loses a value a case depends on. Anything else must be
    /// archived instead; this throws a clear message saying so. Audited.
    /// </summary>
    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var el = await db.DataElements.FirstOrDefaultAsync(e => e.Id == id, ct);
        if (el is null) return;
        if (el.IsSystem)
            throw new InvalidOperationException("Built-in elements can't be deleted — archive it instead.");

        var refCount = await db.CaseDataElements.CountAsync(c => c.ElementKey == el.Key, ct);
        if (refCount > 0)
            throw new InvalidOperationException(
                $"'{el.Label}' is recorded on {refCount} case(s) and can't be deleted — archive it instead.");

        db.DataElements.Remove(el);
        await db.SaveChangesAsync(ct);
    }

    private static IQueryable<DataElement> Ordered(IAppDbContext db) =>
        db.DataElements.AsNoTracking().OrderBy(e => e.SortOrder).ThenBy(e => e.Label);

    private static DataElementView Project(DataElement e, bool referenced) =>
        new(e.Id, e.Key, e.Label, e.SortOrder, e.IsActive, e.IsSystem, e.NotificationJurisdictions, referenced);

    private static string? Normalize(string? jurisdictions)
    {
        if (string.IsNullOrWhiteSpace(jurisdictions)) return null;
        var codes = jurisdictions.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(s => s.ToUpperInvariant()).Distinct();
        var joined = string.Join(",", codes);
        return joined.Length == 0 ? null : joined;
    }

    // A stable, unique PascalCase machine key derived from the label (e.g. "Health record" → "HealthRecord"),
    // disambiguated with a numeric suffix if needed. Falls back to "Element" for label-less input.
    private static string UniqueKey(string label, ISet<string> used)
    {
        var sb = new StringBuilder(label.Length);
        var capNext = true;
        foreach (var ch in label)
        {
            if (char.IsLetterOrDigit(ch))
            {
                sb.Append(capNext ? char.ToUpperInvariant(ch) : ch);
                capNext = false;
            }
            else capNext = true;
        }
        var baseKey = sb.Length == 0 ? "Element" : sb.ToString();
        if (char.IsDigit(baseKey[0])) baseKey = "E" + baseKey;

        var key = baseKey;
        var n = 2;
        while (used.Contains(key)) key = $"{baseKey}{n++}";
        return key;
    }
}
