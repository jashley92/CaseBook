using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>A role that can see across cases, and the AD groups that confer it.</summary>
public sealed record BroadAccessRow(string RoleName, bool ViewAllCases, bool ViewRestricted, IReadOnlyList<string> Groups);

/// <summary>A restricted case and the individuals with case-specific need-to-know.</summary>
public sealed record RestrictedCaseRow(string CaseNumber, string Title, string? IncidentCommander, IReadOnlyList<string> Assignees,
    bool IsArchived = false);

/// <summary>
/// A person CaseBook has seen sign in (the <c>AppUser</c> mirror), with the roles AD granted them at that
/// sign-in. <see cref="IsDormant"/> flags accounts idle past <see cref="AccessReviewService.DormantAfter"/>.
/// </summary>
public sealed record KnownUserRow(string DisplayName, string? UserPrincipalName, IReadOnlyList<string> Roles,
    DateTimeOffset LastSeenUtc, bool IsDormant);

public sealed record AccessReview(IReadOnlyList<BroadAccessRow> Broad, IReadOnlyList<RestrictedCaseRow> RestrictedCases,
    IReadOnlyList<KnownUserRow> KnownUsers);

/// <summary>
/// A read-only need-to-know review for auditors (NYDFS): who can currently see restricted cases and
/// why. Broad access comes from roles granting <see cref="Permission.ViewAllCases"/> /
/// <see cref="Permission.ViewRestricted"/> (and the AD groups mapped to them); case-specific access is
/// the incident commander plus assignees. Mirrors the scoping in <c>CaseQueryExtensions.ForUser</c>.
/// PROD-14: also lists everyone who has signed in, with their roles as of that sign-in and when they were
/// last seen, so a periodic user-access review (NYDFS 500.7) can spot dormant accounts that still hold roles.
/// Roles here are a snapshot: AD is the source of truth, and changes take effect at the user's next sign-in.
/// </summary>
public sealed class AccessReviewService
{
    /// <summary>Accounts not seen for this long are flagged dormant in the review.</summary>
    public static readonly TimeSpan DormantAfter = TimeSpan.FromDays(90);

    private readonly IAppDbContextFactory _factory;
    private readonly IClock _clock;
    private readonly ICurrentUser _user;
    private readonly ISecurityEventSink? _siem;

    public AccessReviewService(IAppDbContextFactory factory, IClock clock, ICurrentUser user, ISecurityEventSink? siem = null)
    {
        _factory = factory;
        _clock = clock;
        _user = user;
        _siem = siem;
    }

    public async Task<AccessReview> BuildAsync(CancellationToken ct = default)
    {
        AdminActionPermissions.Require<AccessReviewService>(_user, _siem);   // BUG-22: the page is Administer-gated too
        using var db = _factory.CreateDbContext();
        var roles = await db.Roles.AsNoTracking().ToListAsync(ct);
        var maps = await db.RoleMappings.AsNoTracking().ToListAsync(ct);

        var groupsByRole = maps
            .GroupBy(m => m.RoleName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<string>)g.Select(x => x.AdGroup).OrderBy(x => x).ToList(),
                StringComparer.OrdinalIgnoreCase);

        var broad = roles
            .Select(r => (Role: r, Perms: r.GetPermissions()))
            .Where(x => x.Perms.Contains(Permission.ViewAllCases) || x.Perms.Contains(Permission.ViewRestricted))
            .Select(x => new BroadAccessRow(
                x.Role.Name,
                x.Perms.Contains(Permission.ViewAllCases),
                x.Perms.Contains(Permission.ViewRestricted),
                groupsByRole.TryGetValue(x.Role.Name, out var g) ? g : []))
            .OrderByDescending(b => b.ViewAllCases)
            .ThenBy(b => b.RoleName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var cases = await db.Cases.AsNoTracking()
            // REV-58: archived ones too. Archiving doesn't take anyone's access away (its commander and team can still open
            // it), so a need-to-know review that left them out under-stated who can see restricted matters.
            .Where(c => c.IsRestricted)
            .Select(c => new { c.Id, c.CaseNumber, c.Title, c.IncidentCommander, c.IsArchived })
            .OrderBy(c => c.IsArchived).ThenBy(c => c.CaseNumber)
            .ToListAsync(ct);

        var caseIds = cases.Select(c => c.Id).ToList();
        var assignments = await db.Assignments.AsNoTracking()
            .Where(a => caseIds.Contains(a.CaseId))
            .Select(a => new { a.CaseId, a.UserId, a.UserDisplayName })
            .ToListAsync(ct);

        var assigneesByCase = assignments
            .GroupBy(a => a.CaseId)
            .ToDictionary(g => g.Key,
                g => (IReadOnlyList<string>)g.Select(a => a.UserDisplayName ?? a.UserId).Distinct().OrderBy(x => x).ToList());

        var restricted = cases
            .Select(c => new RestrictedCaseRow(
                c.CaseNumber, c.Title, c.IncidentCommander,
                assigneesByCase.TryGetValue(c.Id, out var a) ? a : [], c.IsArchived))
            .ToList();

        var now = _clock.UtcNow;
        var users = await db.Users.AsNoTracking().ToListAsync(ct);
        var roleNames = roles.Select(r => r.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var known = users
            .Where(u => !string.Equals(u.Sid, "system", StringComparison.OrdinalIgnoreCase))
            .Select(u => new KnownUserRow(
                string.IsNullOrWhiteSpace(u.DisplayName) ? u.Sid : u.DisplayName,
                string.IsNullOrWhiteSpace(u.UserPrincipalName) ? null : u.UserPrincipalName,
                Domain.Common.RoleList.Split(u.RolesCsv, roleNames.Contains),   // BUG-591: a legacy name with a comma is one role
                u.LastSeenUtc,
                now - u.LastSeenUtc > DormantAfter))
            .OrderByDescending(u => u.IsDormant)
            .ThenBy(u => u.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new AccessReview(broad, restricted, known);
    }
}
