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

/// <summary>
/// CAP-27: one page of the library. <paramref name="HasNext"/> and <paramref name="HasPrevious"/> say whether rows follow
/// it or come before it; <paramref name="Matched"/> is how many the filter matched and <paramref name="FirstIndex"/> where
/// in that order the page starts (0-based), both as they stood when this page was read.
/// </summary>
public sealed record IndicatorLibrary(IndicatorSummary Summary, IReadOnlyList<IndicatorRow> Rows, bool HasNext,
    bool HasPrevious = false, int Matched = 0, int FirstIndex = 0);

/// <summary>
/// CAP-27: where an indicator sits in the library's order: most-shared first, then most recently seen, then by its
/// value (case-insensitively) and type family, so no two indicators share a place.
/// </summary>
public readonly record struct IndicatorPosition(int CaseCount, DateTimeOffset LastSeenUtc, string Key, EntityType Family)
{
    public static IndicatorPosition Of(IndicatorRow r) =>
        new(r.CaseCount, r.LastSeenUtc, r.Value.ToLowerInvariant(), IocObservable.MatchFamily(r.Type));

    /// <summary>Negative when <paramref name="a"/> comes before <paramref name="b"/> in the library's order.</summary>
    public static int Compare(IndicatorPosition a, IndicatorPosition b)
    {
        var c = b.CaseCount.CompareTo(a.CaseCount);
        if (c != 0) return c;
        c = b.LastSeenUtc.CompareTo(a.LastSeenUtc);
        if (c != 0) return c;
        c = string.CompareOrdinal(a.Key, b.Key);
        return c != 0 ? c : a.Family.CompareTo(b.Family);
    }
}

/// <summary>
/// CAP-27: which page of the library to read, by where the page shown starts or ends rather than by its number (keyset
/// paging, as CAP-03's audit trail): the library changes as analysts record indicators, and an offset moves under the
/// reader, so Next would repeat rows just shown and Previous skip some. <see cref="First"/> is the first page;
/// <see cref="Next"/> the rows after the last one shown; <see cref="Previous"/> the rows before the first one shown.
/// </summary>
/// <remarks>B4 review: <see cref="From"/> is the first row of the page Next left (it's read only when
/// <see cref="After"/> is null, as the page starting at that row, inclusive). Previous from an empty page past the end goes
/// back there: going back from Next's own place, exclusively, read the page that ended one row before the page left.</remarks>
public readonly record struct IndicatorPageAt(IndicatorPosition? After, IndicatorPosition? Before, IndicatorPosition? From = null)
{
    public static IndicatorPageAt First => default;
    public static IndicatorPageAt Next(IndicatorRow lastShown, IndicatorRow? firstShown = null) =>
        new(IndicatorPosition.Of(lastShown), null, firstShown is null ? null : IndicatorPosition.Of(firstShown));
    public static IndicatorPageAt Previous(IndicatorRow firstShown) => new(null, IndicatorPosition.Of(firstShown));

    /// <summary>The page before the one read at this place, which showed <paramref name="shown"/>: the rows before its first,
    /// or, for an empty page past the end, the page Next left, from its first row.</summary>
    public IndicatorPageAt PreviousFrom(IReadOnlyList<IndicatorRow> shown)
    {
        ArgumentNullException.ThrowIfNull(shown);
        if (shown.Count > 0) return Previous(shown[0]);
        if (After is not null && From is { } from) return new(null, null, from);
        return After is { } after ? new(null, after) : First;
    }
}

/// <summary>CAP-27: the library as its CSV reads it: every matching indicator up to the limit, with its cases' numbers.</summary>
public sealed record IndicatorExport(IReadOnlyList<IndicatorRow> Rows, int Matched, bool Truncated);

/// <summary>
/// PROD-10: the cross-case indicator pivot ("this indicator appears in N cases") — a lightweight internal
/// library built from the entities analysts already record, so a shared IP/domain/hash surfaces as a pattern
/// instead of staying buried inside one case's "also in" badge. Read-only presentation over existing data:
/// need-to-know scoped exactly like the campaign walk and the overlap engine (an occurrence on a case the
/// viewer can't see is never counted or listed), exercise cases left out unless asked for, and matching is
/// by type family (an account and an email address are one identity, HR-03) + case-insensitive value, the same rule
/// as <see cref="CaseService.FindEntityOverlapsAsync"/>.
/// </summary>
public sealed class IndicatorService
{
    /// <summary>Rows on one page; the summary always counts the whole library. CAP-27: the rest are a page away.</summary>
    public const int PageSize = 300;

    /// <summary>CAP-27: the most indicators one CSV holds; a cut file says so at the top and the end.</summary>
    public const int ExportLimit = 50_000;

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

    /// <summary>The first page of the library for <paramref name="filter"/>.</summary>
    public Task<IndicatorLibrary> SearchAsync(IndicatorFilter filter, CancellationToken ct = default) =>
        SearchAsync(filter, IndicatorPageAt.First, PageSize, ct);

    /// <summary>
    /// CAP-27: one page of the library, <paramref name="at"/> the page shown (keyset, <see cref="IndicatorPageAt"/>). A
    /// Previous page that reaches the start is the first page, full.
    /// </summary>
    public async Task<IndicatorLibrary> SearchAsync(IndicatorFilter filter, IndicatorPageAt at, int pageSize = PageSize,
        CancellationToken ct = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(pageSize, 1);
        using var db = _factory.CreateDbContext();
        var (all, ordered) = await MatchAsync(db, filter, ct);

        var summary = new IndicatorSummary(
            Indicators: all.Count,
            Shared: all.Count(r => r.CaseCount > 1),
            Malicious: all.Count(r => r.WorstDisposition == EntityDisposition.Malicious),
            InOpenCases: all.Count(r => r.OpenCaseCount > 0));

        // CAP-27: from the row the page shown ended (Next) or started (Previous) at, wherever that place is now; a row since
        // gone (or moved) still marks a place in the order.
        int start;
        if (at.Before is { } before)
        {
            var end = ordered.FindIndex(r => IndicatorPosition.Compare(IndicatorPosition.Of(r), before) >= 0);
            start = Math.Max(0, (end < 0 ? ordered.Count : end) - pageSize);
        }
        else if (at.After is { } after)
        {
            start = ordered.FindIndex(r => IndicatorPosition.Compare(IndicatorPosition.Of(r), after) > 0);
            if (start < 0) start = ordered.Count;
        }
        else if (at.From is { } from)
        {
            // B4 review: the page Next left, from its first row (inclusive), wherever that place is now.
            start = ordered.FindIndex(r => IndicatorPosition.Compare(IndicatorPosition.Of(r), from) >= 0);
            if (start < 0) start = Math.Max(0, ordered.Count - pageSize);
        }
        else start = 0;

        var shown = ordered.Skip(start).Take(pageSize).ToList();
        var shownCases = shown.SelectMany(r => r.Cases.Select(c => c.CaseId)).Distinct().ToList();
        var names = await db.Cases.AsNoTracking().Where(c => shownCases.Contains(c.Id))
            .Select(c => new { c.Id, c.CaseNumber, c.Title }).ToDictionaryAsync(c => c.Id, ct);
        shown = shown.Select(r => r with
        {
            Cases = r.Cases.Select(c => names.TryGetValue(c.CaseId, out var n) ? c with { CaseNumber = n.CaseNumber, Title = n.Title } : c).ToList()
        }).ToList();
        return new IndicatorLibrary(summary, shown, HasNext: start + shown.Count < ordered.Count, HasPrevious: start > 0,
            Matched: ordered.Count, FirstIndex: start);
    }

    /// <summary>
    /// CAP-27: every indicator <paramref name="filter"/> matches, in the library's order, up to <paramref name="limit"/>
    /// (and whether more matched), each with its cases' numbers and verdicts: the Indicators page's CSV. The same read as
    /// the page (<see cref="MatchAsync"/>), so need-to-know, the exercise rule and every filter are the page's own.
    /// </summary>
    public async Task<IndicatorExport> ExportAsync(IndicatorFilter filter, int limit = ExportLimit, CancellationToken ct = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        using var db = _factory.CreateDbContext();
        var (_, ordered) = await MatchAsync(db, filter, ct);
        var kept = ordered.Take(limit).ToList();
        // Numbers only (no titles), from the same scoped cases the occurrences were joined to.
        var wanted = kept.SelectMany(r => r.Cases.Select(c => c.CaseId)).ToHashSet();
        var numbers = (await db.Cases.AsNoTracking().ForUser(_user).Select(c => new { c.Id, c.CaseNumber }).ToListAsync(ct))
            .Where(c => wanted.Contains(c.Id)).ToDictionary(c => c.Id, c => c.CaseNumber);
        kept = kept.Select(r => r with
        {
            Cases = r.Cases.Select(c => numbers.TryGetValue(c.CaseId, out var n) ? c with { CaseNumber = n } : c).ToList()
        }).ToList();
        return new IndicatorExport(kept, ordered.Count, ordered.Count > limit);
    }

    // CAP-27: the whole library and the rows the filter matches, in the library's order (IndicatorPosition): the page's and
    // the CSV's one read (C2). Case numbers and titles are left blank, for the caller to fill for the rows it keeps.
    private sealed record Matched(List<IndicatorRow> All, List<IndicatorRow> Ordered);

    private async Task<Matched> MatchAsync(IAppDbContext db, IndicatorFilter filter, CancellationToken ct)
    {
        var cases = db.Cases.AsNoTracking().ForUser(_user);
        if (!filter.IncludeExercises) cases = cases.ExcludingExercises();

        var entities = db.CaseEntities.AsNoTracking();
        // HR-03: a type filter takes in the type's match family (an account and an email address are one identity).
        if (filter.Type is { } t)
        {
            var family = IocObservable.FamilyTypes(t);
            entities = entities.Where(e => family.Contains(e.Type));
        }
        else if (filter.Scope == IndicatorTypeScope.Indicators) entities = entities.Where(e => IocTypes.Contains(e.Type));

        // BUG-253: the summary counts the whole library, so every visible occurrence is read, but narrowly: case numbers
        // and titles (the widest columns, repeated on every row) are read afterwards for the rows shown only.
        var raw = await (
            from e in entities
            join c in cases on e.CaseId equals c.Id
            select new
            {
                e.Type, e.Value, e.Disposition, e.CreatedAtUtc,
                c.Id, c.Classification, c.Phase, c.IsExercise
            }).ToListAsync(ct);

        // Group in memory: case-insensitive value, and DateTimeOffset aggregation stays off SQLite (F-08).
        var all = raw
            .GroupBy(r => (Type: IocObservable.MatchFamily(r.Type), Key: r.Value.Trim().ToLowerInvariant()))
            .Select(g =>
            {
                var perCase = g.GroupBy(x => x.Id)
                    .Select(cg =>
                    {
                        // One line per case: the worst verdict and earliest sighting on that case.
                        var worst = cg.OrderByDescending(x => Severity(x.Disposition)).First();
                        return new IndicatorCase(cg.Key, "", "", worst.Classification,
                            worst.Phase, worst.Disposition, cg.Min(x => x.CreatedAtUtc), worst.IsExercise);
                    })
                    .OrderByDescending(c => c.AddedAtUtc)
                    .ToList();
                return new IndicatorRow(
                    g.OrderByDescending(x => x.CreatedAtUtc).First().Type,   // the latest recorded type within the family
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

        // Most-shared first (the pivot's point), then most recently seen. CAP-27: then by value and type family, so every
        // row has its own place and a page can start after one.
        var ordered = matched
            .Order(Comparer<IndicatorRow>.Create((a, b) => IndicatorPosition.Compare(IndicatorPosition.Of(a), IndicatorPosition.Of(b))))
            .ToList();
        return new Matched(all, ordered);
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
