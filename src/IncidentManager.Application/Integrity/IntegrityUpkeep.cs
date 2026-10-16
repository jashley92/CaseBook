namespace IncidentManager.Application.Integrity;

/// <summary>
/// C18: a change CaseBook makes to keep its own records rather than one anybody made to a case: a derived value filled in
/// (a notice's kept deadline, a reported case's kept jurisdictions) or a record's row hash recorded at the upgrade. It's
/// an audited update like any other, so the row hash and the trail agree, but it carries this reason, and every view
/// of who changed what (changes after closure, the activity feed, the Desk, last activity) leaves it out. The reason is
/// set through <see cref="Abstractions.IAppDbContext.PendingUpkeep"/>, never from text a user typed (the interceptor
/// refuses that text as a reason).
/// </summary>
public static class IntegrityUpkeep
{
    /// <summary>The reason on an upkeep update.</summary>
    public const string Reason = "CaseBook upkeep: not a change to the record";

    /// <summary>Whether a reason a user gave reads as the upkeep reason (refused, so nobody can hide a change as upkeep).</summary>
    public static bool Mimics(string? reason) =>
        reason is not null && reason.Trim().StartsWith("CaseBook upkeep", StringComparison.OrdinalIgnoreCase);
}
