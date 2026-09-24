using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Mitre;

/// <summary>A case counted in the heatmap (the drill-down behind a cell).</summary>
public sealed record CoverageCase(Guid CaseId, string CaseNumber, string Title);

/// <summary>
/// One parent technique under one tactic: how many visible cases exercised it (the parent itself or any of its
/// sub-techniques), which sub-techniques were recorded, and the cases behind the count.
/// </summary>
public sealed record CoverageTechnique(string TechniqueId, string Name, IReadOnlyList<string> SubTechniques,
    IReadOnlyList<CoverageCase> Cases)
{
    public int CaseCount => Cases.Count;
}

/// <summary>A tactic column: distinct cases touching the tactic at all, and its techniques (most-seen first).</summary>
public sealed record CoverageTactic(MitreTactic Tactic, IReadOnlyList<CoverageCase> Cases, IReadOnlyList<CoverageTechnique> Techniques)
{
    public int CaseCount => Cases.Count;
}

/// <param name="CasesInPeriod">Visible cases in the window (the denominator).</param>
/// <param name="CasesWithAttackData">Of those, how many carry any technique or tactic tag.</param>
/// <param name="MaxTechniqueCases">The busiest cell's case count, for scaling the heat.</param>
public sealed record AttackCoverage(int CasesInPeriod, int CasesWithAttackData, IReadOnlyList<CoverageTactic> Tactics,
    int MaxTechniqueCases);

/// <summary>
/// PROD-42: the program-wide ATT&amp;CK heatmap — what the SOC has actually faced, across every case the viewer
/// can see. Aggregates the case technique tags (<c>CaseTechnique</c>) and the event-timeline steps (their
/// technique and tactics) into tactic columns, rolling sub-techniques up to their parent so the matrix stays
/// readable. A case counts once per cell however many times it was tagged. Need-to-know scoped like the
/// campaign walk; exercise cases excluded unless asked for. Read-only presentation, no new data.
/// </summary>
public sealed class AttackCoverageService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public AttackCoverageService(IAppDbContextFactory factory, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
    }

    /// <param name="months">Look-back window by detection date (else open date); null = all time.</param>
    public Task<AttackCoverage> GetAsync(int? months = 12, bool includeExercises = false, CancellationToken ct = default) =>
        GetForPeriodAsync(months is { } m ? _clock.UtcNow.AddMonths(-m) : null, null, includeExercises, ct);

    /// <summary>E-31: the same aggregation over cases detected in [<paramref name="since"/>, <paramref name="until"/>).</summary>
    public async Task<AttackCoverage> GetForPeriodAsync(DateTimeOffset? since, DateTimeOffset? until,
        bool includeExercises = false, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var q = db.Cases.AsNoTracking().ForUser(_user);
        if (!includeExercises) q = q.ExcludingExercises();

        var caseRows = await q.Select(c => new { c.Id, c.CaseNumber, c.Title, c.DetectedAtUtc, c.CreatedAtUtc }).ToListAsync(ct);
        // Window filter in memory: DateTimeOffset comparison stays off SQLite (F-08).
        var inPeriod = caseRows
            .Where(c => (since is null || (c.DetectedAtUtc ?? c.CreatedAtUtc) >= since)
                        && (until is null || (c.DetectedAtUtc ?? c.CreatedAtUtc) < until))
            .ToDictionary(c => c.Id, c => new CoverageCase(c.Id, c.CaseNumber, c.Title));
        var ids = inPeriod.Keys.ToList();

        var tags = await db.CaseTechniques.AsNoTracking()
            .Where(t => ids.Contains(t.CaseId))
            .Select(t => new { t.CaseId, t.TechniqueId, t.Tactic })
            .ToListAsync(ct);
        var steps = await db.TimelineEntries.AsNoTracking()
            .Where(e => ids.Contains(e.CaseId) && e.Kind == TimelineKind.Event)
            .Select(e => new { e.CaseId, e.TechniqueId, Tactics = e.Tactics.Select(x => x.Tactic).ToList() })
            .ToListAsync(ct);

        // Flatten every observation to (case, tactic, technique?) — a tactic-only step still lights its column.
        var obs = new List<(Guid CaseId, MitreTactic Tactic, string? Technique)>();
        foreach (var t in tags)
            foreach (var tac in TacticsFor(t.TechniqueId, [t.Tactic]))
                obs.Add((t.CaseId, tac, t.TechniqueId));
        foreach (var s in steps)
            foreach (var tac in TacticsFor(s.TechniqueId, s.Tactics))
                obs.Add((s.CaseId, tac, s.TechniqueId));

        var tactics = obs
            .GroupBy(o => o.Tactic)
            .Select(g => new CoverageTactic(
                g.Key,
                Distinct(g.Select(o => o.CaseId), inPeriod),
                g.Where(o => !string.IsNullOrWhiteSpace(o.Technique))
                    .GroupBy(o => ParentId(o.Technique!), StringComparer.OrdinalIgnoreCase)
                    .Select(tg => new CoverageTechnique(
                        tg.Key,
                        AttackCatalog.Find(tg.Key)?.Name ?? tg.Key,
                        tg.Select(o => o.Technique!.Trim().ToUpperInvariant())
                            .Where(x => !string.Equals(x, tg.Key, StringComparison.OrdinalIgnoreCase))
                            .Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList(),
                        Distinct(tg.Select(o => o.CaseId), inPeriod)))
                    .OrderByDescending(t => t.CaseCount)
                    .ThenBy(t => t.TechniqueId, StringComparer.Ordinal)
                    .ToList()))
            .OrderBy(t => (int)t.Tactic)
            .ToList();

        return new AttackCoverage(
            inPeriod.Count,
            obs.Select(o => o.CaseId).Distinct().Count(),
            tactics,
            tactics.SelectMany(t => t.Techniques).Select(t => t.CaseCount).DefaultIfEmpty(0).Max());
    }

    /// <summary>
    /// The tactic column(s) an observation belongs in: the tactics recorded with it, else the catalog's tactics
    /// for its technique (a technique tagged without a tactic still lands somewhere), else nowhere.
    /// </summary>
    private static IEnumerable<MitreTactic> TacticsFor(string? techniqueId, IReadOnlyCollection<MitreTactic> recorded)
    {
        var real = recorded.Where(t => t != MitreTactic.Unspecified).Distinct().ToList();
        if (real.Count > 0) return real;
        if (AttackCatalog.Find(techniqueId) is { } t) return t.Tactics.Where(x => x != MitreTactic.Unspecified);
        return [];
    }

    /// <summary>"T1566.001" → "T1566"; normalised upper-case.</summary>
    public static string ParentId(string techniqueId)
    {
        var id = techniqueId.Trim().ToUpperInvariant();
        var dot = id.IndexOf('.');
        return dot < 0 ? id : id[..dot];
    }

    private static IReadOnlyList<CoverageCase> Distinct(IEnumerable<Guid> ids, IReadOnlyDictionary<Guid, CoverageCase> cases) =>
        ids.Distinct().Select(id => cases[id]).OrderBy(c => c.CaseNumber, StringComparer.Ordinal).ToList();
}
