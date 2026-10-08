using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Dashboards;

/// <summary>An open vendor case: whose it is, its attack steps at the vendor and in our environment, and whether the
/// vendor has told us yet (a "vendor notified us" disclosure milestone).</summary>
public sealed record VendorCaseRow(Guid Id, string CaseNumber, string Vendor, int StepsAtVendor, int StepsInOurs, bool Notified);

/// <param name="Open">Vendor (third-party origin) cases open now.</param>
/// <param name="Vendors">Distinct vendors among the vendor cases opened in the period.</param>
/// <param name="Pivoted">Vendor cases opened in the period with an attack step in our environment.</param>
/// <param name="MedianDaysToTellUs">Over the period's vendor cases with both: the median days from the first attack
/// step at the vendor to the vendor notifying us.</param>
public sealed record VendorCases(int Open, int Vendors, int Pivoted, double? MedianDaysToTellUs, int TellUsBasis,
    IReadOnlyList<VendorCaseRow> OpenCases);

/// <summary>The Program overview's vendor-case panel, from third-party cases' attack steps and disclosure milestones
/// (<see cref="EventSteps"/>). Read-only and scoped like every metric.</summary>
public sealed class VendorCasesService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;

    public VendorCasesService(IAppDbContextFactory factory, ICurrentUser user)
    {
        _factory = factory;
        _user = user;
    }

    public async Task<VendorCases> GetAsync(ProgramWindow period, bool includeExercises = false, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var cases = db.Cases.AsNoTracking().ForUser(_user).Where(c => c.Origin == CaseOrigin.ThirdParty && !c.IsArchived);
        if (!includeExercises) cases = cases.ExcludingExercises();

        var rows = (await cases.Select(c => new
            {
                c.Id, c.CaseNumber, c.Phase, c.CreatedAtUtc,
                Vendor = c.ThirdParty != null ? c.ThirdParty.VendorName : null
            }).ToListAsync(ct))
            .Where(c => c.Phase != CasePhase.Closed || (c.CreatedAtUtc >= period.StartUtc && c.CreatedAtUtc < period.EndUtc))
            .ToList();
        var ids = rows.Select(r => r.Id).ToList();
        var steps = (await db.TimelineEntries.AsNoTracking()
                .Where(e => ids.Contains(e.CaseId) && e.Kind == TimelineKind.Event && e.IsCurrent).ToListAsync(ct))
            .GroupBy(e => e.CaseId).ToDictionary(g => g.Key, g => g.ToList());

        var summaries = rows.Select(r =>
        {
            var es = steps.GetValueOrDefault(r.Id) ?? [];
            var attack = es.Where(e => EventSteps.IsAttack(CaseOrigin.ThirdParty, e)).ToList();
            var atVendor = attack.Where(e => EventSteps.Where(CaseOrigin.ThirdParty, e) == StepEnvironment.Vendor).ToList();
            var told = es.Where(e => !EventSteps.HasAttackContent(e) && e.Type == TimelineEntryType.Notified)
                .Select(e => (DateTimeOffset?)e.OccurredAtUtc).Min();
            double? days = atVendor.Count > 0 && told is { } t ? (t - atVendor.Min(e => e.OccurredAtUtc)).TotalDays : null;
            return (Row: r, AtVendor: atVendor.Count, InOurs: attack.Count - atVendor.Count, Told: told is not null, Days: days,
                InPeriod: r.CreatedAtUtc >= period.StartUtc && r.CreatedAtUtc < period.EndUtc);
        }).ToList();

        var inPeriod = summaries.Where(s => s.InPeriod).ToList();
        var days = inPeriod.Where(s => s.Days is >= 0).Select(s => s.Days!.Value).OrderBy(d => d).ToList();
        double? median = days.Count == 0 ? null
            : Math.Round(days.Count % 2 == 1 ? days[days.Count / 2] : (days[days.Count / 2 - 1] + days[days.Count / 2]) / 2, 1);

        return new VendorCases(
            summaries.Count(s => s.Row.Phase != CasePhase.Closed),
            inPeriod.Select(s => s.Row.Vendor?.Trim()).Where(v => !string.IsNullOrEmpty(v)).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            inPeriod.Count(s => s.InOurs > 0),
            median, days.Count,
            summaries.Where(s => s.Row.Phase != CasePhase.Closed)
                .OrderByDescending(s => s.InOurs > 0).ThenByDescending(s => s.Row.CreatedAtUtc)
                .Select(s => new VendorCaseRow(s.Row.Id, s.Row.CaseNumber, s.Row.Vendor ?? "Vendor not named",
                    s.AtVendor, s.InOurs, s.Told))
                .ToList());
    }
}
