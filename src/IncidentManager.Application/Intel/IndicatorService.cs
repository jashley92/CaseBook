using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.Observables;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Intel;

/// <summary>Which entity types the indicator library lists.</summary>
public enum IndicatorTypeScope
{
    /// <summary>Network/file indicators a control can act on (IP, domain, URL, hash) — the default.</summary>
    Indicators = 0,
    /// <summary>Every entity type, including assets (accounts, hosts) and free-form artifacts.</summary>
    AllTypes = 1,
}

/// <param name="Search">Substring match on the value (a defanged paste is refanged first).</param>
/// <param name="Type">A single type, overriding <paramref name="Scope"/> when set.</param>
/// <param name="SharedOnly">Only indicators seen on two or more cases.</param>
/// <param name="Disposition">Only indicators whose worst verdict across cases is this.</param>
public sealed record IndicatorFilter(
    string? Search = null,
    IndicatorTypeScope Scope = IndicatorTypeScope.Indicators,
    EntityType? Type = null,
    bool SharedOnly = false,
    EntityDisposition? Disposition = null,
    bool IncludeExercises = false);

/// <summary>One case an indicator appears on, with the verdict recorded on that case.</summary>
public sealed record IndicatorCase(Guid CaseId, string CaseNumber, string Title, Classification? Classification,
    CasePhase Phase, EntityDisposition Disposition, DateTimeOffset AddedAtUtc, bool IsExercise);

/// <summary>An indicator deduped across the viewer's cases by (type, value), case-insensitively.</summary>
public sealed record IndicatorRow(EntityType Type, string Value, EntityDisposition WorstDisposition,
    DateTimeOffset FirstSeenUtc, DateTimeOffset LastSeenUtc, IReadOnlyList<IndicatorCase> Cases)
{
    public int CaseCount => Cases.Count;
    public int OpenCaseCount => Cases.Count(c => c.Phase != CasePhase.Closed);
}

public sealed record IndicatorSummary(int Indicators, int Shared, int Malicious, int InOpenCases);

/// <param name="Truncated">True when more rows matched than <see cref="IndicatorService.MaxRows"/>; narrow the search.</param>
public sealed record IndicatorLibrary(IndicatorSummary Summary, IReadOnlyList<IndicatorRow> Rows, bool Truncated);

/// <summary>
/// PROD-10: the cross-case indicator pivot ("this indicator appears in N cases") — a lightweight internal
/// library built from the entities analysts already record, so a shared IP/domain/hash surfaces as a pattern
/// instead of staying buried inside one case's "also in" badge. Read-only presentation over existing data:
/// need-to-know scoped exactly like the campaign walk and the overlap engine (an occurrence on a case the
/// viewer can't see is never counted or listed), exercise cases left out unless asked for, and matching is
/// by type + case-insensitive value, the same rule as <see cref="CaseService.FindEntityOverlapsAsync"/>.
/// </summary>
public sealed class IndicatorService
{
    /// <summary>Row cap for one page of results; the summary always counts the whole library.</summary>
    public const int MaxRows = 300;

    private static readonly EntityType[] IocTypes =
        [EntityType.IpAddress, EntityType.Domain, EntityType.Url, EntityType.FileHash];

    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;

    public IndicatorService(IAppDbContextFactory factory, ICurrentUser user)
    {
        _factory = factory;
        _user = user;
    }

    /// <summary>Verdict severity for "worst across cases": malicious outranks compromised, then suspicious.</summary>
    public static int Severity(EntityDisposition d) => d switch
    {
        EntityDisposition.Malicious => 4,
        EntityDisposition.Compromised => 3,
        EntityDisposition.Suspicious => 2,
        EntityDisposition.Unknown => 1,
        _ => 0, // Benign
    };

    public async Task<IndicatorLibrary> SearchAsync(IndicatorFilter filter, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();

        var cases = db.Cases.AsNoTracking().ForUser(_user);
        if (!filter.IncludeExercises) cases = cases.ExcludingExercises();

        var entities = db.CaseEntities.AsNoTracking();
        if (filter.Type is { } t) entities = entities.Where(e => e.Type == t);
        else if (filter.Scope == IndicatorTypeScope.Indicators) entities = entities.Where(e => IocTypes.Contains(e.Type));

        var raw = await (
            from e in entities
            join c in cases on e.CaseId equals c.Id
            select new
            {
                e.Type, e.Value, e.Disposition, e.CreatedAtUtc,
                c.Id, c.CaseNumber, c.Title, c.Classification, c.Phase, c.IsExercise
            }).ToListAsync(ct);

        // Group in memory: case-insensitive value, and DateTimeOffset aggregation stays off SQLite (F-08).
        var all = raw
            .GroupBy(r => (r.Type, Key: r.Value.Trim().ToLowerInvariant()))
            .Select(g =>
            {
                var perCase = g.GroupBy(x => x.Id)
                    .Select(cg =>
                    {
                        // One line per case: the worst verdict and earliest sighting on that case.
                        var worst = cg.OrderByDescending(x => Severity(x.Disposition)).First();
                        return new IndicatorCase(cg.Key, worst.CaseNumber, worst.Title, worst.Classification,
                            worst.Phase, worst.Disposition, cg.Min(x => x.CreatedAtUtc), worst.IsExercise);
                    })
                    .OrderByDescending(c => c.AddedAtUtc)
                    .ToList();
                return new IndicatorRow(
                    g.Key.Type,
                    g.OrderByDescending(x => x.CreatedAtUtc).First().Value.Trim(),
                    perCase.Select(c => c.Disposition).MaxBy(Severity),
                    g.Min(x => x.CreatedAtUtc),
                    g.Max(x => x.CreatedAtUtc),
                    perCase);
            })
            .ToList();

        var term = string.IsNullOrWhiteSpace(filter.Search) ? null : IocObservable.Refang(filter.Search.Trim());
        IEnumerable<IndicatorRow> matched = all;
        if (term is { Length: > 0 })
            matched = matched.Where(r => r.Value.Contains(term, StringComparison.OrdinalIgnoreCase));
        if (filter.SharedOnly) matched = matched.Where(r => r.CaseCount > 1);
        if (filter.Disposition is { } d) matched = matched.Where(r => r.WorstDisposition == d);

        // Most-shared first (the pivot's point), then most recently seen.
        var ordered = matched
            .OrderByDescending(r => r.CaseCount)
            .ThenByDescending(r => r.LastSeenUtc)
            .ThenBy(r => r.Value, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var summary = new IndicatorSummary(
            Indicators: all.Count,
            Shared: all.Count(r => r.CaseCount > 1),
            Malicious: all.Count(r => r.WorstDisposition == EntityDisposition.Malicious),
            InOpenCases: all.Count(r => r.OpenCaseCount > 0));

        return new IndicatorLibrary(summary, ordered.Take(MaxRows).ToList(), ordered.Count > MaxRows);
    }

    /// <summary>
    /// Resolves an entity id (from a case's IOC table) to its value for a pivot link, so the value itself never
    /// rides in a URL. Need-to-know scoped: an entity on a case the viewer can't see resolves to null.
    /// </summary>
    public async Task<(EntityType Type, string Value)?> ResolveEntityAsync(Guid entityId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var hit = await (
            from e in db.CaseEntities.AsNoTracking()
            where e.Id == entityId
            join c in db.Cases.AsNoTracking().ForUser(_user) on e.CaseId equals c.Id
            select new { e.Type, e.Value }).FirstOrDefaultAsync(ct);
        return hit is null ? null : (hit.Type, hit.Value);
    }
}
