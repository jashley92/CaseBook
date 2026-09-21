using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

public static class CaseQueryExtensions
{
    /// <summary>Applies need-to-know scoping so a user only sees cases they are entitled to.</summary>
    public static IQueryable<Case> ForUser(this IQueryable<Case> query, ICurrentUser user)
    {
        // Need-to-know is keyed on capabilities, not specific roles, so a custom role granting either
        // capability behaves correctly without touching this scoping logic:
        //   • ViewAllCases — full leadership/oversight: every case, restricted or not.
        //   • ViewRestricted (F-22) — clearance to open restricted (need-to-know) cases, held by roles that
        //     work sensitive matters without the org-wide oversight ViewAllCases implies (IncidentCommander,
        //     LegalPrivacy). Under this single scoping gate both converge on "see everything", but they are
        //     distinct grants; wiring ViewRestricted here makes the permission enforce what its name and the
        //     access-review report already claim (it was previously declared and displayed but never consulted).
        if (user.Has(Permission.ViewAllCases) || user.Has(Permission.ViewRestricted)) return query;

        // Otherwise: every non-restricted case, plus any restricted case the user commands or is assigned to.
        var uid = user.UserId;
        return query.Where(c =>
            !c.IsRestricted
            || c.IncidentCommander == uid
            || c.Assignments.Any(a => a.UserId == uid));
    }

    /// <summary>
    /// PROD-43: drops tabletop/exercise cases. Applied at every org-posture aggregate, automated reminder,
    /// pushed feed, and cross-case IOC-correlation query, so a drill never pollutes real metrics or gets
    /// suggested for linking to a live case. Deliberately NOT part of <see cref="ForUser"/> — an exercise
    /// case must stay fully visible in its own workspace and (on request) the case list; this only strips it
    /// from the aggregate/automation surfaces.
    /// </summary>
    public static IQueryable<Case> ExcludingExercises(this IQueryable<Case> query) =>
        query.Where(c => !c.IsExercise);
}
