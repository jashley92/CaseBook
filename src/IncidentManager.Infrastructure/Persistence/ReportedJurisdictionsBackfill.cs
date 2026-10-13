using IncidentManager.Application.Compliance;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// WF-11: a case reported before CaseBook recorded which jurisdictions were in play gets them now, so a later change to a
/// data element's jurisdictions doesn't reopen or re-judge it. Its notices name them when it has any (it was reported
/// once each was notified); otherwise today's settings are the best record there is. A no-op once every reported case has
/// them. Runs at start-up, as the system.
/// </summary>
public static class ReportedJurisdictionsBackfill
{
    public static async Task<int> RunAsync(AppDbContext db, CancellationToken ct = default)
    {
        var cases = await db.Cases.AsSplitQuery().Include(c => c.DataElements).Include(c => c.JurisdictionNotices)   // S8733
            .Where(c => c.ReportedAtUtc != null && c.ReportedJurisdictions == null)
            .ToListAsync(ct);
        foreach (var c in cases)
        {
            IEnumerable<string> codes = c.JurisdictionNotices.Count > 0
                ? c.JurisdictionNotices.Select(n => n.Jurisdiction)
                : await NotificationDeadlineService.JurisdictionsInPlayAsync(db, c.DataElements.Select(d => d.ElementKey), ct);
            c.ReportedJurisdictions = string.Join(',', codes.Select(j => j.Trim().ToUpperInvariant()).Where(j => j.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(j => j, StringComparer.Ordinal));
        }
        if (cases.Count > 0) await db.SaveChangesAsync(ct);
        return cases.Count;
    }
}
