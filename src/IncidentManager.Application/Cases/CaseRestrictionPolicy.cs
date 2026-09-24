using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>
/// S-08: who may restrict a case to need-to-know, and who may lift it. Restricting narrows exposure, so anyone
/// who can edit the case may do it (the service adds them to the case team first if they'd otherwise lose sight of
/// it). Lifting widens exposure to everyone with case access, so it's held to the case's incident commander or a
/// role cleared for restricted cases, and needs a reason. Mirrors the scoping rule in
/// <see cref="CaseQueryExtensions.ForUser"/> so the two can't drift.
/// </summary>
public static class CaseRestrictionPolicy
{
    /// <summary>Whether the user holds a clearance that sees every restricted case.</summary>
    public static bool HasClearance(ICurrentUser user) =>
        user.Has(Permission.ViewAllCases) || user.Has(Permission.ViewRestricted);

    /// <summary>Whether the user would still see the case once it's restricted.</summary>
    public static bool KeepsAccess(ICurrentUser user, string? incidentCommander, IEnumerable<string> assigneeIds) =>
        HasClearance(user)
        || string.Equals(incidentCommander, user.UserId, StringComparison.Ordinal)
        || assigneeIds.Any(a => string.Equals(a, user.UserId, StringComparison.Ordinal));

    /// <summary>Whether the user may lift the restriction (widening who can see the case).</summary>
    public static bool CanLift(ICurrentUser user, string? incidentCommander) =>
        HasClearance(user) || string.Equals(incidentCommander, user.UserId, StringComparison.Ordinal);
}
