using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Views;

/// <summary>A saved case-queue view as shown in the views menu.</summary>
/// <param name="IsMine">True when the current user owns it (and so may rename/share/delete it).</param>
/// <param name="OwnerName">Display name of the owner, for shared views from someone else.</param>
public sealed record SavedViewItem(Guid Id, string Name, string Query, bool IsShared, bool IsMine, string OwnerName, bool IsDefault);

/// <summary>
/// Persists named case-queue filter sets (PROD-09 / E-02b). Each view is the exact Cases query string plus
/// a name; personal by default, or shared to the whole team. Users manage their own views; shared views
/// from others are read-only (apply only). This is convenience state — out of the tamper-evident chain.
/// </summary>
public sealed class SavedViewService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IUserDirectory _users;
    private readonly IClock _clock;

    public SavedViewService(IAppDbContextFactory factory, ICurrentUser user, IUserDirectory users, IClock clock)
    {
        _factory = factory;
        _user = user;
        _users = users;
        _clock = clock;
    }

    /// <summary>The current user's own views plus everyone's shared views, for the menu. Own first, then shared.</summary>
    public async Task<List<SavedViewItem>> ListAsync(CancellationToken ct = default)
    {
        var me = _user.UserId;
        using var db = _factory.CreateDbContext();
        var rows = await db.SavedViews.AsNoTracking()
            .Where(v => v.OwnerUserId == me || v.IsShared)
            .ToListAsync(ct);

        return rows
            .Select(v => new SavedViewItem(
                v.Id, v.Name, v.Query, v.IsShared,
                IsMine: string.Equals(v.OwnerUserId, me, StringComparison.OrdinalIgnoreCase),
                OwnerName: string.Equals(v.OwnerUserId, me, StringComparison.OrdinalIgnoreCase) ? "you" : _users.DisplayFor(v.OwnerUserId),
                // A default only applies to its owner's own landing (never inherited from someone's shared view).
                IsDefault: v.IsDefault && string.Equals(v.OwnerUserId, me, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(v => v.IsMine)
            .ThenBy(v => v.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// PROD-24: toggle which of the current user's own views is their default landing view. Setting one
    /// clears the rest (at most one default per user); calling it on the current default clears it.
    /// Returns the id that is now the default, or null if none.
    /// </summary>
    public async Task<Guid?> ToggleDefaultAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var me = _user.UserId;

        var target = await db.SavedViews.FirstOrDefaultAsync(v => v.Id == id, ct);
        if (target is null) return null;
        if (!string.Equals(target.OwnerUserId, me, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("You can only set one of your own views as default.");

        var mine = await db.SavedViews.Where(v => v.OwnerUserId == me && v.IsDefault).ToListAsync(ct);
        var wasDefault = target.IsDefault;
        foreach (var v in mine) v.IsDefault = false; // clear any existing default
        target.IsDefault = !wasDefault;              // toggle the target
        await db.SaveChangesAsync(ct);
        return target.IsDefault ? target.Id : null;
    }

    /// <summary>The current user's default landing view (the query to apply on a bare /cases), or null.</summary>
    public async Task<SavedViewItem?> DefaultAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var me = _user.UserId;
        var v = await db.SavedViews.AsNoTracking()
            .FirstOrDefaultAsync(x => x.OwnerUserId == me && x.IsDefault, ct);
        return v is null ? null
            : new SavedViewItem(v.Id, v.Name, v.Query, v.IsShared, IsMine: true, OwnerName: "you", IsDefault: true);
    }

    /// <summary>
    /// Creates or updates the current user's view of the given name (upsert by owner+name, matching the
    /// unique index), so "save" over an existing name updates it rather than erroring. Returns its id.
    /// </summary>
    public async Task<Guid> SaveAsync(string name, string query, bool isShared, CancellationToken ct = default)
    {
        var cleanName = (name ?? "").Trim();
        if (string.IsNullOrWhiteSpace(cleanName)) throw new ArgumentException("A view name is required.");
        if (cleanName.Length > 120) throw new ArgumentException("A view name must be 120 characters or fewer.");
        var cleanQuery = NormalizeQuery(query);

        using var db = _factory.CreateDbContext();
        var me = _user.UserId;
        var existing = await db.SavedViews.FirstOrDefaultAsync(
            v => v.OwnerUserId == me && v.Name == cleanName, ct);

        if (existing is null)
        {
            var view = new SavedView
            {
                OwnerUserId = me,
                Name = cleanName,
                Query = cleanQuery,
                IsShared = isShared,
                CreatedAtUtc = _clock.UtcNow,
            };
            db.SavedViews.Add(view);
            await db.SaveChangesAsync(ct);
            return view.Id;
        }

        existing.Query = cleanQuery;
        existing.IsShared = isShared;
        await db.SaveChangesAsync(ct);
        return existing.Id;
    }

    /// <summary>Deletes one of the current user's own views. Shared views from others cannot be deleted here.</summary>
    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var me = _user.UserId;
        var view = await db.SavedViews.FirstOrDefaultAsync(v => v.Id == id, ct);
        if (view is null) return;
        if (!string.Equals(view.OwnerUserId, me, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("You can only delete your own saved views.");
        db.SavedViews.Remove(view);
        await db.SaveChangesAsync(ct);
    }

    // Store the query without a leading '?' and trimmed; cap to the column length.
    private static string NormalizeQuery(string? query)
    {
        var q = (query ?? "").Trim().TrimStart('?');
        return q.Length > 2000 ? q[..2000] : q;
    }
}
