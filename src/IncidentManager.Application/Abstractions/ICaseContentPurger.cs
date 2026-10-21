namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Marks for deletion everything filed under a removed case (its timeline, notes, tasks, IOCs, brief, reports' rows, links
/// to and from other cases, and the rest) in the caller's context, so the purge is one save: one transaction, each row's
/// deletion in the audit trail. Leaves the case's own row, its evidence records and their chain of custody, which the
/// audit trail and the custody history point to.
/// </summary>
public interface ICaseContentPurger
{
    /// <summary>Loads and removes the case's content rows in <paramref name="db"/> (not saved); returns how many.</summary>
    Task<int> RemoveContentAsync(IAppDbContext db, Guid caseId, CancellationToken ct = default);
}
