using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>One member's row in the taxonomy admin view: its default, any override, effective label, and
/// (for kinds that allow it) whether it is hidden from pick-lists. Members are returned in effective order.</summary>
public sealed record TaxonomyMemberView(string Value, string DefaultLabel, string? Override, string Effective, bool Hidden)
{
    public bool IsOverridden => Override is not null;
}

/// <summary>A taxonomy with its members' effective labels, for the admin UI. BUG-438: <paramref name="Stamp"/> stands for
/// the kind's stored order and hidden rows, for <see cref="TaxonomyAdminService.SetVisibilityOrderAsync"/>.</summary>
public sealed record TaxonomyKindView(string Id, string Title, string Description, bool AllowVisibilityOrder, IReadOnlyList<TaxonomyMemberView> Members,
    string Stamp = "");

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
    internal const int MaxLabelLength = 60;

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
            return new TaxonomyKindView(k.Id, k.Title, k.Description, k.AllowVisibilityOrder, members,
                StampOf(k, key => overrides.TryGetValue(key, out var v) ? v : null));
        }).ToList();
    }

    // BUG-438: the kind's stored order and hidden rows (whatever their case or value), as a hash.
    private static string StampOf(TaxonomyKind k, Func<string, string?> stored)
    {
        var parts = new List<string> { stored(TaxonomyCatalog.OrderKey(k.Id)) ?? "" };
        parts.AddRange(k.Members.Select(m => stored(TaxonomyCatalog.HiddenKey(k.Id, m.Value)) is { } h ? m.Value + "=" + h : ""));
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(string.Join("\u0001", parts))));
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
        AdminActionPermissions.Require<TaxonomyAdminService>(_user);
        await SaveLabelsAsync(kind, new Dictionary<string, string?>(StringComparer.Ordinal) { [member] = label }, ct);
    }

    /// <summary>
    /// BUG-378: several members' labels (member to label; blank or default clears it) in one save, so a card saves all
    /// its labels or none. Everything is checked before anything is written.
    /// </summary>
    public async Task SetLabelAsync(string kind, IReadOnlyDictionary<string, string?> labels, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<TaxonomyAdminService>(_user);
        await SaveLabelsAsync(kind, labels, ct);
    }

    private async Task SaveLabelsAsync(string kind, IReadOnlyDictionary<string, string?> labels, CancellationToken ct)
    {
        var k = TaxonomyCatalog.Kinds.FirstOrDefault(x => x.Id == kind)
            ?? throw new InvalidOperationException($"'{kind}' is not a known taxonomy.");
        var edits = new List<(string Key, string? Value)>();
        foreach (var (member, label) in labels)
        {
            var def = k.Members.FirstOrDefault(m => m.Value == member)
                ?? throw new InvalidOperationException($"'{member}' is not a member of '{kind}'.");
            var trimmed = label?.Trim();
            // Blank, or the same as the built-in default: don't persist a redundant override.
            var redundant = string.IsNullOrWhiteSpace(trimmed) || string.Equals(trimmed, def.DefaultLabel, StringComparison.Ordinal);
            if (!redundant && trimmed!.Length > MaxLabelLength)
                throw new ArgumentException($"A label must be {MaxLabelLength} characters or fewer.");
            edits.Add((TaxonomyCatalog.LabelKey(kind, member), redundant ? null : trimmed));
        }
        if (edits.Count == 0) return;

        // BUG-437: a reset (or change) of a label another save removed meanwhile is refused by the context as a
        // ConcurrentEditException, and the whole save rolls back. Labels have no stamp (each is set as typed), so it goes
        // again from a fresh read: a label already gone is then left alone.
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                await SaveLabelEditsAsync(edits, ct);
                return;
            }
            catch (ConcurrentEditException) when (attempt < 2) { }
        }
    }

    private async Task SaveLabelEditsAsync(List<(string Key, string? Value)> edits, CancellationToken ct)
    {
        using var db = _factory.CreateDbContext();
        var keys = edits.Select(e => e.Key).ToList();
        var rows = await db.AppSettings.Where(s => keys.Contains(s.Key)).ToListAsync(ct);
        var added = new List<string>();
        var changed = false;
        foreach (var (key, value) in edits)
        {
            var existing = rows.FirstOrDefault(r => string.Equals(r.Key, key, StringComparison.OrdinalIgnoreCase));
            if (value is null)
            {
                if (existing is null) continue;
                db.AppSettings.Remove(existing);
            }
            // BUG-378: a label that already has an override is changed in place. It was always added, so the unique index
            // refused every change to one.
            else if (existing is null) Add(db, added, key, value);
            else if (!string.Equals(existing.Value, value, StringComparison.Ordinal)) Touch(existing, value);
            else continue;
            changed = true;
        }
        if (!changed) return;
        await SaveAsync(db, added, ct);
        _reloader.ReloadOrThrow();   // BUG-270
    }

    /// <summary>
    /// Sets the pick-list <b>order</b> and <b>hidden</b> members for one kind (X-02 slice 3). The kind must
    /// allow it (the ladder and phases don't); <paramref name="orderedMembers"/> must be exactly the kind's
    /// members, in the desired order; and at least one member must remain visible. Redundant rows are removed:
    /// an order equal to the built-in order stores nothing, and only hidden members keep a hidden row. Audited.
    /// BUG-438: <paramref name="expectedStamp"/> is the kind's <see cref="TaxonomyKindView.Stamp"/> when the page loaded; the
    /// save writes the whole order and hidden set, so one another administrator changed since is refused. Null skips the
    /// check. Returns the kind's stamp after the save.
    /// </summary>
    public async Task<string> SetVisibilityOrderAsync(string kind, IReadOnlyList<string> orderedMembers, IReadOnlyCollection<string> hiddenMembers,
        string? expectedStamp = null, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<TaxonomyAdminService>(_user);
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
        if (expectedStamp is not null && !string.Equals(StampOf(k, key => Find(key)?.Value), expectedStamp, StringComparison.Ordinal))
            throw StaleOrder(k);

        var changed = false;
        var added = new List<string>();

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
            if (existingOrder is null) { Add(db, added, orderKey, csv); changed = true; }
            else if (!string.Equals(existingOrder.Value, csv, StringComparison.Ordinal)) { Touch(existingOrder, csv); changed = true; }
        }

        // Hidden: a row per hidden member; remove rows for members that are (now) visible.
        var hidden = hiddenMembers.ToHashSet(StringComparer.Ordinal);
        foreach (var m in k.Members)
        {
            var hkey = TaxonomyCatalog.HiddenKey(kind, m.Value);
            var existing = Find(hkey);
            if (hidden.Contains(m.Value))
            {
                if (existing is null) { Add(db, added, hkey, "true"); changed = true; }
                else if (!string.Equals(existing.Value, "true", StringComparison.OrdinalIgnoreCase)) { Touch(existing, "true"); changed = true; }
            }
            else if (existing is not null)
            {
                db.AppSettings.Remove(existing);
                changed = true;
            }
        }

        if (changed)
        {
            // BUG-438: a row this changes or removes went between the read above and this save.
            try { await SaveAsync(db, added, ct); }
            catch (ConcurrentEditException ex) { throw StaleOrder(k, ex); }
            _reloader.Reload();
        }
        // The rows as saved (Local leaves out the removed ones), so the page can save again without reloading the card.
        var stamp = StampOf(k, key => db.AppSettings.Local.FirstOrDefault(r => string.Equals(r.Key, key, StringComparison.OrdinalIgnoreCase))?.Value);
        // BUG-270 / BUG-526: saved but not in effect; the new stamp travels with it, so the page's next save isn't refused as stale.
        if (changed) _reloader.ThrowIfNotInEffect(stamp);
        return stamp;
    }

    private static InvalidOperationException StaleOrder(TaxonomyKind k, Exception? inner = null) =>
        new($"Someone changed the order or hidden options of {k.Title} since you opened it, so nothing was saved: " +
            "it would have undone that. Reload the page, then make your change again.", inner);

    private void Add(IAppDbContext db, List<string> added, string key, string value)
    {
        db.AppSettings.Add(new AppSetting
        {
            Key = key,
            Value = value,
            UpdatedAtUtc = _clock.UtcNow,
            UpdatedBy = _user.UserId
        });
        added.Add(key);
    }

    private void Touch(AppSetting row, string value)
    {
        row.Value = value;
        row.UpdatedAtUtc = _clock.UtcNow;
        row.UpdatedBy = _user.UserId;
    }

    // BUG-393: another administrator's save added the same override between the read above and this insert (the unique
    // index refused it). Said plainly, not an error page; nothing from this save is kept.
    private async Task SaveAsync(IAppDbContext db, List<string> added, CancellationToken ct)
    {
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException ex) when (added.Count > 0)
        {
            using var recheck = _factory.CreateDbContext();
            if (await recheck.AppSettings.AnyAsync(s => added.Contains(s.Key), ct))
                throw new InvalidOperationException(
                    "Another administrator saved this taxonomy at the same moment. Reload the page to see their change, then save again.", ex);
            throw;
        }
    }

    /// <summary>Removes a member's override so it reverts to the built-in default. Audited. No-op if unset.</summary>
    public Task ResetAsync(string kind, string member, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<TaxonomyAdminService>(_user);
        return SetLabelAsync(kind, member, null, ct);
    }
}
