using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Views;

/// <summary>A saved case-queue view as shown in the views menu.</summary>
/// <param name="IsMine">True when the current user owns it (and so may rename/share/delete it).</param>
/// <param name="OwnerName">Display name of the owner, for shared views from someone else.</param>
/// <param name="TeamId">CAP-36: with <paramref name="IsShared"/>, the team it's shared with (null: everyone).</param>
/// <param name="TeamName">CAP-36: that team's name, for the menu.</param>
public sealed record SavedViewItem(Guid Id, string Name, string Query, bool IsShared, bool IsMine, string OwnerName, bool IsDefault,
    Guid? TeamId = null, string? TeamName = null);

/// <summary>
/// Persists named case-queue filter sets (PROD-09 / E-02b). Each view is the exact Cases query string plus
/// a name; personal by default, or shared to the whole team. Users manage their own views; shared views
/// from others are read-only (apply only). This is convenience state — out of the tamper-evident chain.
/// CAP-36: a view can be shared with one team instead of everyone: only that team's members (and its owner) see it. A
/// view holds a filter, never cases: whoever applies it still sees only the cases need-to-know lets them see.
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

    /// <summary>The current user's own views plus the views shared with everyone or with a team they're in, for the menu.
    /// Own first, then shared.</summary>
    public async Task<List<SavedViewItem>> ListAsync(CancellationToken ct = default)
    {
        var me = _user.UserId;
        using var db = _factory.CreateDbContext();
        // CAP-36: the teams I'm in (any, retired too: a view already shared with one stays with its members).
        var mine = await Admin.TeamService.TeamsOfAsync(db, me, ct);   // CAP-36 review: ignoring case, as everywhere
        var rows = await db.SavedViews.AsNoTracking()
            .Where(v => v.OwnerUserId == me || (v.IsShared && (v.TeamId == null || mine.Contains(v.TeamId.Value))))
            .ToListAsync(ct);
        var teamIds = rows.Where(v => v.TeamId != null).Select(v => v.TeamId!.Value).Distinct().ToList();
        var teamNames = teamIds.Count == 0 ? new Dictionary<Guid, string>()
            : await db.Teams.AsNoTracking().Where(t => teamIds.Contains(t.Id)).ToDictionaryAsync(t => t.Id, t => t.Name, ct);

        return rows
            .Select(v => new SavedViewItem(
                v.Id, v.Name, v.Query, v.IsShared,
                IsMine: string.Equals(v.OwnerUserId, me, StringComparison.OrdinalIgnoreCase),
                OwnerName: string.Equals(v.OwnerUserId, me, StringComparison.OrdinalIgnoreCase) ? "you" : _users.DisplayFor(v.OwnerUserId),
                // A default only applies to its owner's own landing (never inherited from someone's shared view).
                IsDefault: v.IsDefault && string.Equals(v.OwnerUserId, me, StringComparison.OrdinalIgnoreCase),
                TeamId: v.IsShared ? v.TeamId : null,
                TeamName: v.IsShared && v.TeamId is { } t ? teamNames.GetValueOrDefault(t) : null))
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
        // BUG-540: two quick toggles (two stars, two tabs) each read "no other default" and each set theirs, leaving two.
        // The read and the save run one at a time (CaseBook runs as one instance; see known issues).
        await DefaultGate.WaitAsync(ct);
        try
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
        finally { DefaultGate.Release(); }
    }

    private static readonly SemaphoreSlim DefaultGate = new(1, 1);

    /// <summary>The current user's default landing view (the query to apply on a bare /cases), or null.</summary>
    public async Task<SavedViewItem?> DefaultAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var me = _user.UserId;
        // BUG-540: two defaults stored before the toggle was serialised resolve the same way every time.
        var v = await db.SavedViews.AsNoTracking()
            .Where(x => x.OwnerUserId == me && x.IsDefault)
            .OrderBy(x => x.Name).ThenBy(x => x.Id)
            .FirstOrDefaultAsync(ct);
        return v is null ? null
            : new SavedViewItem(v.Id, v.Name, v.Query, v.IsShared, IsMine: true, OwnerName: "you", IsDefault: true, v.IsShared ? v.TeamId : null);
    }

    /// <summary>
    /// Creates or updates the current user's view of the given name (upsert by owner+name, matching the
    /// unique index), so "save" over an existing name updates it rather than erroring. Returns its id.
    /// CAP-36: <paramref name="teamId"/> shares it with that team only (with <paramref name="isShared"/>): an active team the
    /// user is in.
    /// </summary>
    public async Task<Guid> SaveAsync(string name, string query, bool isShared, CancellationToken ct = default) =>
        await SaveAsync(name, query, isShared, null, ct);

    /// <inheritdoc cref="SaveAsync(string, string, bool, CancellationToken)"/>
    public async Task<Guid> SaveAsync(string name, string query, bool isShared, Guid? teamId, CancellationToken ct = default)
    {
        var cleanName = (name ?? "").Trim();
        if (string.IsNullOrWhiteSpace(cleanName)) throw new ArgumentException("A view name is required.");
        if (cleanName.Length > 120) throw new ArgumentException("A view name must be 120 characters or fewer.");
        var cleanQuery = NormalizeQuery(query);

        var me = _user.UserId;
        if (!isShared) teamId = null;
        if (teamId is { } team)
        {
            // CAP-36: shared with a team the sharer is in (and an active one), never one they'd only name.
            using var check = _factory.CreateDbContext();
            // CAP-36 review: membership ignoring case, as the list above and the Teams page read it.
            if (!(await Admin.TeamService.TeamsOfAsync(check, me, ct)).Contains(team)
                || !await check.Teams.AsNoTracking().AnyAsync(t => t.Id == team && t.IsActive, ct))
                throw new InvalidOperationException("You can share a view only with an active team you're in.");
        }
        // BUG-452: two first saves of the same name (a double click, two tabs) both insert, and the second hits the
        // (OwnerUserId, Name) unique index. That one re-reads the row the first inserted and updates it instead.
        for (var attempt = 0; ; attempt++)
        {
            using var db = _factory.CreateDbContext();
            var existing = await db.SavedViews.FirstOrDefaultAsync(
                v => v.OwnerUserId == me && v.Name == cleanName, ct);
            var adding = existing is null;
            if (existing is null)
            {
                existing = new SavedView
                {
                    OwnerUserId = me,
                    Name = cleanName,
                    CreatedAtUtc = _clock.UtcNow,
                };
                db.SavedViews.Add(existing);
            }
            existing.Query = cleanQuery;
            existing.IsShared = isShared;
            existing.TeamId = teamId;   // CAP-36
            try
            {
                await db.SaveChangesAsync(ct);
                return existing.Id;
            }
            catch (DbUpdateException) when (adding && attempt == 0) { /* lost the insert race: update the row that won */ }
        }
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

    /// <summary>The longest query a view holds (the <c>SavedViews.Query</c> column).</summary>
    public const int MaxQueryLength = 2000;

    // Store the query without a leading '?' and trimmed. BUG-599: one too long for the column is refused; cut short, the
    // view silently kept a different filter (half a search word, a lost sort or page size).
    private static string NormalizeQuery(string? query)
    {
        var q = (query ?? "").Trim().TrimStart('?');
        if (q.Length > MaxQueryLength)
            throw new ArgumentException(string.Create(System.Globalization.CultureInfo.InvariantCulture,
                $"This view's filters are too long to save ({q.Length:N0} characters; a view holds up to {MaxQueryLength:N0}). ") +
                "Shorten the search words or clear a filter, then save again.");
        return q;
    }
}
