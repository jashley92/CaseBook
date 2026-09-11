using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Work;

/// <summary>Which due-date band an agenda item falls into, relative to now (UTC).</summary>
public enum AgendaBucketKind
{
    Overdue,
    Today,
    ThisWeek,
    Later,
    NoDueDate
}

/// <summary>One open after-action item on the agenda board, flattened for display.</summary>
public sealed record AgendaItem(
    Guid CaseId, string CaseNumber, string CaseTitle, Severity Severity,
    Guid ActionItemId, string Title, string? OwnerUserId, DateTimeOffset? DueAtUtc, bool OwnedByMe);

/// <summary>A named band of agenda items (e.g. all overdue), in due order.</summary>
public sealed record AgendaBucket(AgendaBucketKind Kind, IReadOnlyList<AgendaItem> Items);

/// <summary>A selectable owner for the board's owner filter (an owner value + how many open items they hold).</summary>
public sealed record AgendaOwnerOption(string OwnerUserId, int Count);

/// <summary>The agenda board for a scope: the non-empty buckets in order, plus the owner filter options.</summary>
public sealed record AgendaBoard(
    IReadOnlyList<AgendaBucket> Buckets, IReadOnlyList<AgendaOwnerOption> Owners, int TotalCount);

/// <summary>
/// The due-date agenda (E-39): a work-queue view of open after-action items across the caller's visible
/// cases, grouped into due bands (overdue / today / this week / later / undated) and filterable by owner —
/// complementing the personal <see cref="MyWorkService"/> ("my work") and the leadership team view. Also the
/// source for the per-user calendar (ICS) feed. Every read is need-to-know scoped via
/// <see cref="CaseQueryExtensions.ForUser"/>; it records nothing (read-only, out of the audit chain).
/// </summary>
public sealed class AgendaService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IUserDirectory _users;
    private readonly IClock _clock;

    public AgendaService(IAppDbContextFactory factory, ICurrentUser user, IUserDirectory users, IClock clock)
    {
        _factory = factory;
        _user = user;
        _users = users;
        _clock = clock;
    }

    /// <summary>Owner-filter sentinel meaning "only items I own" (matched against all my identifiers).</summary>
    public const string MineOwnerFilter = "@me";

    /// <summary>
    /// Builds the board for the current user. <paramref name="ownerFilter"/> is null/empty for everyone,
    /// <see cref="MineOwnerFilter"/> for the caller's own items, or a specific owner value.
    /// </summary>
    public async Task<AgendaBoard> GetBoardAsync(string? ownerFilter = null, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var now = _clock.UtcNow;

        var rows = await OpenItems(db).ToListAsync(ct);

        // Owner options are over everything the caller can see (before the owner filter narrows the board).
        var owners = rows
            .Where(r => !string.IsNullOrWhiteSpace(r.Owner))
            .GroupBy(r => r.Owner!, StringComparer.OrdinalIgnoreCase)
            .Select(g => new AgendaOwnerOption(g.Key, g.Count()))
            .OrderByDescending(o => o.Count)
            .ThenBy(o => _users.DisplayFor(o.OwnerUserId), StringComparer.OrdinalIgnoreCase)
            .ToList();

        var filtered = rows.Where(r => MatchesOwner(r.Owner, ownerFilter)).ToList();

        var items = filtered
            .Select(r => new AgendaItem(
                r.CaseId, r.CaseNumber, r.CaseTitle, r.Severity, r.ActionItemId, r.Title,
                r.Owner, r.DueAtUtc, OwnedByMe(r.Owner)))
            .ToList();

        var buckets = Enum.GetValues<AgendaBucketKind>()
            .Select(kind => new AgendaBucket(kind, items
                .Where(i => Bucket(i.DueAtUtc, now) == kind)
                .OrderBy(i => i.DueAtUtc ?? DateTimeOffset.MaxValue)
                .ThenBy(i => i.CaseNumber, StringComparer.OrdinalIgnoreCase)
                .ToList()))
            .Where(b => b.Items.Count > 0)
            .ToList();

        return new AgendaBoard(buckets, owners, items.Count);
    }

    /// <summary>
    /// The open, dated after-action items a specific user should see on their personal calendar feed: items
    /// they own, or on a case they command / are assigned to, excluding restricted cases they are not on.
    /// Self-scoping — it only ever returns the user's own work — so it needs no role context.
    /// </summary>
    public async Task<IReadOnlyList<AgendaItem>> GetFeedItemsAsync(string userId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(userId)) return [];
        using var db = _factory.CreateDbContext();

        var rows = await (
            from a in db.ActionItems.AsNoTracking()
            where a.DueAtUtc != null
                  && a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled
            join c in db.Cases.AsNoTracking() on a.CaseId equals c.Id
            where !c.IsArchived
                  && (!c.IsRestricted || c.IncidentCommander == userId || c.Assignments.Any(x => x.UserId == userId))
            select new Row(
                c.Id, c.CaseNumber, c.Title, c.Severity, c.IsRestricted, c.IncidentCommander,
                a.Id, a.Title, a.DueAtUtc, a.Owner,
                c.IncidentCommander == userId || c.Assignments.Any(x => x.UserId == userId)))
            .ToListAsync(ct);

        // "Mine" for an arbitrary user: a task I own (by any identifier), or a case I'm on.
        var ids = Identifiers(userId);
        return rows
            .Where(r => r.IsMine || OwnerMatches(r.Owner, ids))
            .OrderBy(r => r.DueAtUtc ?? DateTimeOffset.MaxValue)
            .Select(r => new AgendaItem(
                r.CaseId, r.CaseNumber, r.CaseTitle, r.Severity, r.ActionItemId, r.Title,
                r.Owner, r.DueAtUtc, OwnerMatches(r.Owner, ids)))
            .ToList();
    }

    private IQueryable<Row> OpenItems(IAppDbContext db) =>
        from a in db.ActionItems.AsNoTracking()
        where a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled
        join c in db.Cases.AsNoTracking().ForUser(_user) on a.CaseId equals c.Id
        where !c.IsArchived
        select new Row(
            c.Id, c.CaseNumber, c.Title, c.Severity, c.IsRestricted, c.IncidentCommander,
            a.Id, a.Title, a.DueAtUtc, a.Owner,
            c.IncidentCommander == _user.UserId || c.Assignments.Any(x => x.UserId == _user.UserId));

    private sealed record Row(
        Guid CaseId, string CaseNumber, string CaseTitle, Severity Severity, bool IsRestricted,
        string? IncidentCommander, Guid ActionItemId, string Title, DateTimeOffset? DueAtUtc, string? Owner,
        bool IsMine);

    /// <summary>Buckets a due date relative to <paramref name="now"/> (UTC calendar day boundaries).</summary>
    private static AgendaBucketKind Bucket(DateTimeOffset? due, DateTimeOffset now)
    {
        if (due is not { } d) return AgendaBucketKind.NoDueDate;
        if (d < now) return AgendaBucketKind.Overdue;

        var startOfTomorrow = now.UtcDateTime.Date.AddDays(1);
        if (d.UtcDateTime < startOfTomorrow) return AgendaBucketKind.Today;
        if (d.UtcDateTime < startOfTomorrow.AddDays(6)) return AgendaBucketKind.ThisWeek; // through end of the week ahead
        return AgendaBucketKind.Later;
    }

    private bool MatchesOwner(string? owner, string? ownerFilter)
    {
        if (string.IsNullOrWhiteSpace(ownerFilter)) return true;               // everyone
        if (ownerFilter == MineOwnerFilter) return OwnedByMe(owner);
        return owner is not null && string.Equals(owner.Trim(), ownerFilter.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    private bool OwnedByMe(string? owner) => OwnerMatches(owner, Identifiers(_user.UserId, _user.UserPrincipalName, _user.DisplayName, _user.Email));

    private IReadOnlyList<string> Identifiers(string userId, params string?[] extra)
    {
        var set = new List<string>();
        void Add(string? v) { if (!string.IsNullOrWhiteSpace(v)) set.Add(v.Trim()); }
        Add(userId);
        foreach (var e in extra) Add(e);
        if (extra.Length == 0 && _users.Resolve(userId) is { } summary)   // enrich a bare id from the directory
        {
            Add(summary.DisplayName);
            Add(summary.Email);
            Add(summary.UserPrincipalName);
        }
        return set;
    }

    private static bool OwnerMatches(string? owner, IReadOnlyList<string> identifiers)
    {
        if (string.IsNullOrWhiteSpace(owner)) return false;
        var o = owner.Trim();
        return identifiers.Any(id => string.Equals(o, id, StringComparison.OrdinalIgnoreCase));
    }
}
