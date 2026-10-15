using IncidentManager.Application.Compliance;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// WF-11: a case reported before CaseBook recorded which jurisdictions were in play gets them now, so a later change to a
/// data element's jurisdictions doesn't reopen or re-judge it. Its notices name them when it has any (it was reported
/// once each was notified); otherwise today's settings are the best record there is. A no-op once every reported case has
/// them. Runs at start-up, as the system. WF-93: written straight to the column (it's derived and kept out of the canonical),
/// not as an audited change: an audited one counted as "1 change after closure by system" on every closed reported case.
/// BUG-563: with the data elements the case has (BUG-284); and a kept value written before the elements were recorded gets
/// them too, so wherever what's in play is read, an element added since is told apart from one the case had.
/// </summary>
public static class ReportedJurisdictionsBackfill
{
    public static async Task<int> RunAsync(AppDbContext db, CancellationToken ct = default)
    {
        var cases = await db.Cases.AsNoTracking().AsSplitQuery().Include(c => c.DataElements).Include(c => c.JurisdictionNotices)   // S8733
            .Where(c => c.ReportedAtUtc != null && c.ReportedJurisdictions == null)
            .ToListAsync(ct);
        foreach (var c in cases)
        {
            IEnumerable<string> codes = c.JurisdictionNotices.Count > 0
                ? c.JurisdictionNotices.SelectMany(n => NotificationDeadlineService.SplitCodes(n.Jurisdiction))   // BUG-428: a legacy "NY;CA" notice
                : await NotificationDeadlineService.JurisdictionsInPlayAsync(db, c.DataElements.Select(d => d.ElementKey), ct);
            var frozen = string.Join(',', codes.Select(j => j.Trim().ToUpperInvariant()).Where(j => j.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(j => j, StringComparer.Ordinal));
            frozen = Case.WithElements(frozen, c.DataElements.Select(d => d.ElementKey)) ?? frozen;
            await db.Cases.Where(x => x.Id == c.Id && x.ReportedJurisdictions == null)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.ReportedJurisdictions, frozen), ct);
        }
        return cases.Count + await KeepElementsAsync(db, ct);
    }

    // BUG-563: a kept value holding only the codes (written before BUG-284) gets the elements the case had. Still reported,
    // that's every element it has: each reader took the kept codes alone, so none was told apart as added. Back to
    // unreported, an element bringing a jurisdiction today that isn't kept is the one that reopened it (one it had brought
    // only kept ones), so it stays in play. Too long to hold them, the value is left as it was.
    private static async Task<int> KeepElementsAsync(AppDbContext db, CancellationToken ct)
    {
        var cases = await db.Cases.AsNoTracking().Include(c => c.DataElements)
            .Where(c => c.ReportedJurisdictions != null && !EF.Functions.Like(c.ReportedJurisdictions, "%;%"))
            .ToListAsync(ct);
        if (cases.Count == 0) return 0;
        var live = NotificationDeadlineService.Live(await NotificationDeadlineService.ElementJurisdictionsAsync(db, ct));
        var written = 0;
        foreach (var c in cases)
        {
            var kept = c.ReportedJurisdictions!;
            var codes = Case.KeptJurisdictions(kept) ?? [];
            var had = c.DataElements.Select(d => d.ElementKey)
                .Where(k => c.ReportedAtUtc is not null || live([k]).All(j => codes.Contains(j, StringComparer.OrdinalIgnoreCase)));
            if (Case.WithElements(kept, had) is not { } withElements) continue;
            written += await db.Cases.Where(x => x.Id == c.Id && x.ReportedJurisdictions == kept)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.ReportedJurisdictions, withElements), ct);
        }
        return written;
    }
}
