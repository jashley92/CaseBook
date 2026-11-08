using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Mitre;

/// <summary>A technique as a tactic's column lists it: the parent, whether it belongs to the tactic itself (or is only a
/// heading for its sub-techniques there), and its sub-techniques in that tactic.</summary>
public sealed record AttackMatrixRow(AttackTechnique Parent, bool ParentInTactic, IReadOnlyList<AttackTechnique> Subs);

/// <summary>A tactic's column of the matrix, its techniques by id.</summary>
public sealed record AttackMatrixColumn(MitreTactic Tactic, IReadOnlyList<AttackMatrixRow> Rows);

/// <summary>A row as the picker draws it for a filter: <see cref="OpenForMatch"/> when a sub-technique matches (so the
/// parent opens to show it), and the sub-techniques it shows when open.</summary>
public sealed record AttackMatrixShownRow(AttackMatrixRow Row, bool OpenForMatch, IReadOnlyList<AttackTechnique> ShownSubs);

/// <summary>A tactic's column for a filter. A <see cref="Hidden"/> column has no match; it stays in the layout so it can
/// fold away smoothly, keeping for that one change the rows it showed before, and none after.</summary>
public sealed record AttackMatrixShownColumn(MitreTactic Tactic, bool Hidden, IReadOnlyList<AttackMatrixShownRow> Rows);

/// <summary>
/// The ATT&amp;CK matrix picker's columns for what's typed in its filter: every tactic, in matrix order, with the box empty;
/// only the tactics with a matching technique while filtering, so they sit side by side. A technique matches on its id or
/// name; a parent is listed when it or one of its sub-techniques matches. Worked out once per filter change, not on every
/// render.
/// </summary>
public sealed class AttackMatrixView
{
    private static readonly Lazy<IReadOnlyList<AttackMatrixColumn>> Catalogue = new(() => Build(AttackCatalog.All));

    /// <summary>The catalogue's matrix, built once.</summary>
    public static IReadOnlyList<AttackMatrixColumn> Matrix => Catalogue.Value;

    /// <summary>The tactics, in matrix order (Reconnaissance first, Impact last).</summary>
    public static IReadOnlyList<MitreTactic> Tactics { get; } =
        Enum.GetValues<MitreTactic>().Where(t => t != MitreTactic.Unspecified).OrderBy(DiagramPalette.TacticRank).ToList();

    /// <summary>The filter, trimmed.</summary>
    public string Filter { get; }

    /// <summary>Whether anything is typed.</summary>
    public bool IsFiltering => Filter.Length > 0;

    /// <summary>Every tactic's column, in matrix order; the hidden ones have no match.</summary>
    public IReadOnlyList<AttackMatrixShownColumn> Columns { get; }

    /// <summary>The tactics with a match (all of them with no filter).</summary>
    public int VisibleTactics { get; }

    /// <summary>The distinct techniques and sub-techniques that match, counted once however many tactics list them.</summary>
    public int MatchingTechniques { get; }

    /// <summary>Filtering and nothing matches.</summary>
    public bool NoMatches => IsFiltering && VisibleTactics == 0;

    /// <summary>The tactics shown, as one string: it changes when, and only when, the columns move.</summary>
    public string Layout { get; }

    private AttackMatrixView(string filter, IReadOnlyList<AttackMatrixShownColumn> columns, int matching)
    {
        Filter = filter;
        Columns = columns;
        MatchingTechniques = matching;
        VisibleTactics = columns.Count(c => !c.Hidden);
        Layout = string.Join(",", columns.Where(c => !c.Hidden).Select(c => (int)c.Tactic));
    }

    /// <summary>"Showing 3 of 15 tactics with matches · 12 techniques" while filtering with matches; null otherwise.</summary>
    public string? Summary => IsFiltering && !NoMatches
        ? $"Showing {VisibleTactics} of {Plural(Columns.Count, "tactic")} with matches · {Plural(MatchingTechniques, "technique")}"
        : null;

    /// <summary>"No techniques match 'xyz'" when filtering finds nothing; null otherwise.</summary>
    public string? NoMatchText => NoMatches ? $"No techniques match '{Filter}'" : null;

    private static string Plural(int n, string noun) => n == 1 ? $"1 {noun}" : $"{n} {noun}s";

    private static readonly Lazy<AttackMatrixView> Everything = new(() => For(Matrix, ""));

    /// <summary>The catalogue's matrix with nothing typed, built once: every tactic, none hidden.</summary>
    public static AttackMatrixView Unfiltered => Everything.Value;

    /// <summary>The catalogue's matrix for <paramref name="filter"/>. With nothing typed it's <see cref="Unfiltered"/>,
    /// whatever came before: no column is hidden, so none keeps rows from <paramref name="previous"/>.</summary>
    public static AttackMatrixView For(string? filter, AttackMatrixView? previous = null) =>
        string.IsNullOrWhiteSpace(filter) ? Unfiltered : For(Matrix, filter, previous);

    /// <summary>
    /// <paramref name="matrix"/> for <paramref name="filter"/>. Given the <paramref name="previous"/> view, a column that has
    /// just lost its matches keeps the rows it showed, so it can fade with them rather than empty first.
    /// </summary>
    public static AttackMatrixView For(IReadOnlyList<AttackMatrixColumn> matrix, string? filter, AttackMatrixView? previous = null)
    {
        var f = (filter ?? "").Trim();
        var matched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var before = previous?.Columns.ToDictionary(c => c.Tactic);
        var columns = new List<AttackMatrixShownColumn>(matrix.Count);
        foreach (var col in matrix)
        {
            var rows = new List<AttackMatrixShownRow>();
            foreach (var row in col.Rows)
            {
                if (Shown(row, f, matched) is { } shown) rows.Add(shown);
            }
            if (rows.Count > 0 || f.Length == 0)
            {
                columns.Add(new AttackMatrixShownColumn(col.Tactic, false, rows));
                continue;
            }
            var leaving = before is not null && before.TryGetValue(col.Tactic, out var was) && !was.Hidden ? was.Rows : [];
            columns.Add(new AttackMatrixShownColumn(col.Tactic, true, leaving));
        }
        return new AttackMatrixView(f, columns, matched.Count);
    }

    // The row as shown for the filter, or null when neither the parent nor any sub-technique matches. A parent that matches
    // shows all its sub-techniques when opened; one listed for its sub-techniques opens to show just the ones that match.
    private static AttackMatrixShownRow? Shown(AttackMatrixRow row, string f, HashSet<string> matched)
    {
        if (f.Length == 0) return new AttackMatrixShownRow(row, false, row.Subs);
        var parentMatches = AttackCatalog.Matches(row.Parent, f);
        var subs = row.Subs.Where(s => AttackCatalog.Matches(s, f)).ToList();
        if (!parentMatches && subs.Count == 0) return null;
        if (parentMatches) matched.Add(row.Parent.Id);
        foreach (var s in subs) matched.Add(s.Id);
        return new AttackMatrixShownRow(row, subs.Count > 0, parentMatches ? row.Subs : subs);
    }

    /// <summary>The matrix: tactics as columns in matrix order, each listing the parents that belong to it or that have a
    /// sub-technique in it, by id, with those sub-techniques under them.</summary>
    public static IReadOnlyList<AttackMatrixColumn> Build(IEnumerable<AttackTechnique> all)
    {
        var list = all.ToList();
        var parents = list.Where(t => !t.IsSubtechnique).ToDictionary(t => t.Id, StringComparer.OrdinalIgnoreCase);
        var subsByParent = list.Where(t => t.IsSubtechnique)
            .GroupBy(t => t.ParentId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderBy(x => x.Id, StringComparer.OrdinalIgnoreCase).ToList(), StringComparer.OrdinalIgnoreCase);

        var cols = new List<AttackMatrixColumn>();
        foreach (var tac in Tactics)
        {
            // A parent that's there only for its subs is a heading: clicking it opens them rather than tagging it.
            var ids = parents.Values.Where(p => p.Tactics.Contains(tac)).Select(p => p.Id)
                .Concat(subsByParent.Where(kv => kv.Value.Exists(s => s.Tactics.Contains(tac))).Select(kv => kv.Key))
                .Where(parents.ContainsKey)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase);

            var rows = ids.Select(pid =>
            {
                var parent = parents[pid];
                IReadOnlyList<AttackTechnique> subs = subsByParent.TryGetValue(pid, out var sl) ? sl.Where(s => s.Tactics.Contains(tac)).ToList() : [];
                return new AttackMatrixRow(parent, parent.Tactics.Contains(tac), subs);
            }).ToList();
            cols.Add(new AttackMatrixColumn(tac, rows));
        }
        return cols;
    }
}
