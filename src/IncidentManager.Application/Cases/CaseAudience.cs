using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>
/// S-13: whether a <em>named</em> user (not the caller) can see a case, from the user mirror's roles and the role
/// directory — the same rule <see cref="CaseQueryExtensions.ForUser"/> applies to the signed-in user. Used to keep
/// notifications (an @mention email, a picker of people to mention) inside a restricted case's audience.
/// </summary>
public static class CaseAudience
{
    public static bool CanSee(bool isRestricted, string? incidentCommander, IEnumerable<string> assigneeIds,
        UserSummary? user, IRoleDirectory roles)
    {
        if (user is null) return false;
        var perms = roles.PermissionsForRoles(
            user.RolesCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        if (!perms.Contains(Permission.ViewCases)) return false;
        if (!isRestricted) return true;
        return perms.Contains(Permission.ViewAllCases) || perms.Contains(Permission.ViewRestricted)
               || string.Equals(incidentCommander, user.UserId, StringComparison.Ordinal)
               || assigneeIds.Any(a => string.Equals(a, user.UserId, StringComparison.Ordinal));
    }
}
