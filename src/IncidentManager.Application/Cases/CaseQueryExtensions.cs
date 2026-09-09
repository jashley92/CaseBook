using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

public static class CaseQueryExtensions
{
    /// <summary>Applies need-to-know scoping so a user only sees cases they are entitled to.</summary>
    public static IQueryable<Case> ForUser(this IQueryable<Case> query, ICurrentUser user)
    {
        // Need-to-know is keyed on a capability, not specific roles, so a custom role granting
        // ViewAllCases behaves correctly without touching this scoping logic.
        if (user.Has(Permission.ViewAllCases)) return query;

        var uid = user.UserId;
        return query.Where(c =>
            !c.IsRestricted
            || c.IncidentCommander == uid
            || c.Assignments.Any(a => a.UserId == uid));
    }
}
