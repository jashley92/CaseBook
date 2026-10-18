using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Cases;

/// <summary>
/// CAP-36: a team filter, as the Cases list, its CSV, Find, Program and Team workload apply it: every case (no filter), the
/// cases with no team, or one team's. It only narrows what need-to-know already let through: callers apply it after
/// <c>ForUser</c>/<c>Scoped</c>, never instead (ADR 0003), so a team filter can't bring a restricted case into view.
/// A key no team has matches nothing (a stale link lists nothing rather than everything).
/// </summary>
public readonly record struct TeamScope(Guid? Id, bool Unowned)
{
    /// <summary>The URL value for the cases with no team (<c>team=none</c>).</summary>
    public const string NoneKey = "none";

    /// <summary>No team filter.</summary>
    public static TeamScope Any => default;

    /// <summary>The cases with no team.</summary>
    public static TeamScope NoTeam => new(null, true);

    /// <summary>One team's cases.</summary>
    public static TeamScope Of(Guid id) => new(id, false);

    /// <summary>A key no team has: matches no case.</summary>
    public static TeamScope Nothing => new(Guid.Empty, false);

    public bool IsAny => Id is null && !Unowned;

    /// <summary>The scope a URL's <c>team=</c> value names: blank is every case, <c>none</c> the cases with no team, a key that
    /// team's (ignoring case), and anything else nothing.</summary>
    public static async Task<TeamScope> ResolveAsync(IAppDbContext db, string? key, CancellationToken ct = default)
    {
        var k = key?.Trim();
        if (string.IsNullOrEmpty(k)) return Any;
        if (string.Equals(k, NoneKey, StringComparison.OrdinalIgnoreCase)) return NoTeam;
        if (k.Length > Team.KeyMax) return Nothing;
        // Keys are ASCII letters and digits (TeamService.UniqueKey): compared ignoring case in memory, the same on either database.
        var teams = await db.Teams.AsNoTracking().Select(t => new { t.Id, t.Key }).ToListAsync(ct);
        return teams.FirstOrDefault(t => string.Equals(t.Key, k, StringComparison.OrdinalIgnoreCase)) is { } hit ? Of(hit.Id) : Nothing;
    }
}

public static class TeamScopeQueries
{
    /// <summary>CAP-36: the cases <paramref name="scope"/> keeps, from cases already scoped to the caller.</summary>
    public static IQueryable<Case> InTeam(this IQueryable<Case> cases, TeamScope scope)
    {
        if (scope.Unowned) return cases.Where(c => c.TeamId == null);
        if (scope.Id is { } id) return cases.Where(c => c.TeamId == id);
        return cases;
    }
}
