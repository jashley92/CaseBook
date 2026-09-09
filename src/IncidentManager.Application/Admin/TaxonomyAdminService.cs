using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>One member's row in the taxonomy admin view: its default, any override, effective label, and
/// (for kinds that allow it) whether it is hidden from pick-lists. Members are returned in effective order.</summary>
public sealed record TaxonomyMemberView(string Value, string DefaultLabel, string? Override, string Effective, bool Hidden)
{
    public bool IsOverridden => Override is not null;
}

/// <summary>A taxonomy with its members' effective labels, for the admin UI.</summary>
public sealed record TaxonomyKindView(string Id, string Title, string Description, bool AllowVisibilityOrder, IReadOnlyList<TaxonomyMemberView> Members);

/// <summary>
/// Reads and writes the admin-editable <b>display</b> of the code-defined taxonomies (X-02): member labels for
/// every kind, plus <b>hidden</b> and <b>order</b> for the pick-list kinds (slice 3). Overrides are stored as
/// <c>Taxonomy:{Kind}:{Label|Hidden}:{Member}</c> / <c>Taxonomy:{Kind}:Order</c> rows in the same audited
/// settings table as operational settings, so each change is attributable and hash-chained. Redundant rows (a
/// label equal to the default, a hidden=false, an order equal to the built-in order) are removed rather than
/// stored. A write reloads configuration so the change takes effect at runtime with no restart.
/// </summary>
public sealed class TaxonomyAdminService
{
    private const int MaxLabelLength = 60;

    private readonly IAppDbContextFactory _factory;
    private readonly IClock _clock;
    private readonly ICurrentUser _user;
    private readonly ISettingsReloader _reloader;

    public TaxonomyAdminService(IAppDbContextFactory factory, IClock clock, ICurrentUser user, ISettingsReloader reloader)
    {
        _factory = factory;
        _clock = clock;
        _user = user;
        _reloader = reloader;
    }

    /// <summary>Every taxonomy and member with its default, current override, effective label and hidden flag,
    /// with members in effective (admin-configured) order.</summary>
    public async Task<IReadOnlyList<TaxonomyKindView>> GetEffectiveAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var overrides = await db.AppSettings.AsNoTracking()
            .Where(s => s.Key.StartsWith(TaxonomyCatalog.KeyPrefix))
            .ToDictionaryAsync(s => s.Key, s => s.Value, StringComparer.OrdinalIgnoreCase, ct);

        return TaxonomyCatalog.Kinds.Select(k =>
        {
            var ordered = OrderMembers(k, overrides);
            var members = ordered.Select(m =>
            {
                overrides.TryGetValue(TaxonomyCatalog.LabelKey(k.Id, m.Value), out var ov);
                var trimmed = string.IsNullOrWhiteSpace(ov) ? null : ov!.Trim();
                var hidden = k.AllowVisibilityOrder
                    && overrides.TryGetValue(TaxonomyCatalog.HiddenKey(k.Id, m.Value), out var h)
                    && bool.TryParse(h, out var b) && b;
                return new TaxonomyMemberView(m.Value, m.DefaultLabel, trimmed, trimmed ?? m.DefaultLabel, hidden);
            }).ToList();
            return new TaxonomyKindView(k.Id, k.Title, k.Description, k.AllowVisibilityOrder, members);
        }).ToList();
    }

    // Catalog members reordered by the stored Order CSV (listed members first, in CSV order; the rest keep
    // their catalog order). Only meaningful for AllowVisibilityOrder kinds; others always use catalog order.
    private static IReadOnlyList<TaxonomyMember> OrderMembers(TaxonomyKind k, IReadOnlyDictionary<string, string?> overrides)
    {
        if (!k.AllowVisibilityOrder || !overrides.TryGetValue(TaxonomyCatalog.OrderKey(k.Id), out var csv) || string.IsNullOrWhiteSpace(csv))
            return k.Members;

        var order = csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        int Rank(TaxonomyMember m)
        {
            var i = order.IndexOf(m.Value);
            return i >= 0 ? i : order.Count + k.Members.ToList().IndexOf(m);
        }
        return k.Members.OrderBy(Rank).ToList();
    }

    /// <summary>
    /// Sets (or, for a blank/default value, clears) the display label for one taxonomy member. Rejects
    /// unknown kinds/members and over-long labels. Audited and hash-chained via the settings table.
    /// </summary>
    public async Task SetLabelAsync(string kind, string member, string? label, CancellationToken ct = default)
    {
        var k = TaxonomyCatalog.Kinds.FirstOrDefault(x => x.Id == kind)
            ?? throw new InvalidOperationException($"'{kind}' is not a known taxonomy.");
        var def = k.Members.FirstOrDefault(m => m.Value == member)
            ?? throw new InvalidOperationException($"'{member}' is not a member of '{kind}'.");

        var trimmed = label?.Trim();
        var key = TaxonomyCatalog.LabelKey(kind, member);

        using var db = _factory.CreateDbContext();
        var existing = await db.AppSettings.FirstOrDefaultAsync(s => s.Key == key, ct);

        // Blank, or the same as the built-in default → don't persist a redundant override.
        if (string.IsNullOrWhiteSpace(trimmed) || string.Equals(trimmed, def.DefaultLabel, StringComparison.Ordinal))
        {
            if (existing is null) return;
            db.AppSettings.Remove(existing);
            await db.SaveChangesAsync(ct);
            _reloader.Reload();
            return;
        }

        if (trimmed.Length > MaxLabelLength)
            throw new ArgumentException($"A label must be {MaxLabelLength} characters or fewer.");

        Upsert(db, key, trimmed);
        await db.SaveChangesAsync(ct);
        _reloader.Reload();
    }

    /// <summary>
    /// Sets the pick-list <b>order</b> and <b>hidden</b> members for one kind (X-02 slice 3). The kind must
    /// allow it (the ladder and phases don't); <paramref name="orderedMembers"/> must be exactly the kind's
    /// members, in the desired order; and at least one member must remain visible. Redundant rows are removed:
    /// an order equal to the built-in order stores nothing, and only hidden members keep a hidden row. Audited.
    /// </summary>
    public async Task SetVisibilityOrderAsync(string kind, IReadOnlyList<string> orderedMembers, IReadOnlyCollection<string> hiddenMembers, CancellationToken ct = default)
    {
        var k = TaxonomyCatalog.Kinds.FirstOrDefault(x => x.Id == kind)
            ?? throw new InvalidOperationException($"'{kind}' is not a known taxonomy.");
        if (!k.AllowVisibilityOrder)
            throw new InvalidOperationException($"'{kind}' does not support hiding or reordering.");

        var catalogValues = k.Members.Select(m => m.Value).ToHashSet(StringComparer.Ordinal);
        if (orderedMembers.Count != catalogValues.Count || !orderedMembers.All(catalogValues.Contains) || orderedMembers.Distinct(StringComparer.Ordinal).Count() != orderedMembers.Count)
            throw new InvalidOperationException($"The order for '{kind}' must list each of its members exactly once.");
        foreach (var h in hiddenMembers)
            if (!catalogValues.Contains(h)) throw new InvalidOperationException($"'{h}' is not a member of '{kind}'.");
        if (hiddenMembers.Count >= catalogValues.Count)
            throw new ArgumentException("At least one option must stay visible.");

        using var db = _factory.CreateDbContext();
        var rows = await db.AppSettings
            .Where(s => s.Key.StartsWith(TaxonomyCatalog.KeyPrefix + kind + ":"))
            .ToListAsync(ct);
        AppSetting? Find(string key) => rows.FirstOrDefault(r => string.Equals(r.Key, key, StringComparison.OrdinalIgnoreCase));

        var changed = false;

        // Order: store only when it differs from the built-in (catalog) order.
        var orderKey = TaxonomyCatalog.OrderKey(kind);
        var isDefaultOrder = orderedMembers.SequenceEqual(k.Members.Select(m => m.Value), StringComparer.Ordinal);
        var existingOrder = Find(orderKey);
        if (isDefaultOrder)
        {
            if (existingOrder is not null) { db.AppSettings.Remove(existingOrder); changed = true; }
        }
        else
        {
            var csv = string.Join(",", orderedMembers);
            if (existingOrder is null) { Upsert(db, orderKey, csv); changed = true; }
            else if (!string.Equals(existingOrder.Value, csv, StringComparison.Ordinal)) { existingOrder.Value = csv; existingOrder.UpdatedAtUtc = _clock.UtcNow; existingOrder.UpdatedBy = _user.UserId; changed = true; }
        }

        // Hidden: a row per hidden member; remove rows for members that are (now) visible.
        var hidden = hiddenMembers.ToHashSet(StringComparer.Ordinal);
        foreach (var m in k.Members)
        {
            var hkey = TaxonomyCatalog.HiddenKey(kind, m.Value);
            var existing = Find(hkey);
            if (hidden.Contains(m.Value))
            {
                if (existing is null) { Upsert(db, hkey, "true"); changed = true; }
                else if (!string.Equals(existing.Value, "true", StringComparison.OrdinalIgnoreCase)) { existing.Value = "true"; existing.UpdatedAtUtc = _clock.UtcNow; existing.UpdatedBy = _user.UserId; changed = true; }
            }
            else if (existing is not null)
            {
                db.AppSettings.Remove(existing);
                changed = true;
            }
        }

        if (changed)
        {
            await db.SaveChangesAsync(ct);
            _reloader.Reload();
        }
    }

    private void Upsert(IAppDbContext db, string key, string value) =>
        db.AppSettings.Add(new AppSetting
        {
            Key = key,
            Value = value,
            UpdatedAtUtc = _clock.UtcNow,
            UpdatedBy = _user.UserId
        });

    /// <summary>Removes a member's override so it reverts to the built-in default. Audited. No-op if unset.</summary>
    public Task ResetAsync(string kind, string member, CancellationToken ct = default) =>
        SetLabelAsync(kind, member, null, ct);
}
