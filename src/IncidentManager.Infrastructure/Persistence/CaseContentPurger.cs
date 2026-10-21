using System.Reflection;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// The purge of a removed case's content, read from the model rather than listed by hand, so a table added later that's
/// filed under a case (a required <c>CaseId</c>) is purged with the rest. The rows are loaded and removed in the caller's
/// context, so its one save deletes them (EF orders the deletes) and the audit trail records each; case links go both ways
/// (to the case, and from it). Kept: the case's row, its evidence rows (purged, their custody kept), and the tables with
/// an optional case id (the access log, alert deliveries, held mail), as the context's filter keeps them.
/// </summary>
public sealed class CaseContentPurger : ICaseContentPurger
{
    private static readonly MethodInfo RemoveForMethod =
        typeof(CaseContentPurger).GetMethod(nameof(RemoveFor), BindingFlags.NonPublic | BindingFlags.Static)!;

    public async Task<int> RemoveContentAsync(IAppDbContext context, Guid caseId, CancellationToken ct = default)
    {
        var db = (AppDbContext)context;
        var removed = 0;
        foreach (var type in ContentTables(db.Model))
            removed += await (Task<int>)RemoveForMethod.MakeGenericMethod(type.ClrType).Invoke(null, [db, caseId, ct])!;
        // A link from another case to this one.
        var inbound = await db.CaseLinks.IgnoreQueryFilters().Where(l => l.RelatedCaseId == caseId).ToListAsync(ct);
        db.CaseLinks.RemoveRange(inbound);
        return removed + inbound.Count;
    }

    private static async Task<int> RemoveFor<T>(AppDbContext db, Guid caseId, CancellationToken ct) where T : class
    {
        var rows = await db.Set<T>().IgnoreQueryFilters().Where(e => EF.Property<Guid>(e, "CaseId") == caseId).ToListAsync(ct);
        db.Set<T>().RemoveRange(rows);
        return rows.Count;
    }

    /// <summary>The tables filed under a case (a required Guid <c>CaseId</c>), but not the case, nor its evidence.</summary>
    internal static IReadOnlyList<IEntityType> ContentTables(IModel model) =>
        model.GetEntityTypes()
            .Where(t => !t.IsOwned() && t.ClrType != typeof(Case) && t.ClrType != typeof(Evidence)
                        && t.FindProperty("CaseId") is { } p && p.ClrType == typeof(Guid))
            .ToList();
}
