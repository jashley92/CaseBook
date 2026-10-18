namespace IncidentManager.Application.Evidence;

/// <summary>CAP-25: a quick filter on the Evidence tab's list.</summary>
public enum EvidenceChip
{
    /// <summary>Images (shown inline and in the preview).</summary>
    Images,
    /// <summary>Files whose start can be read as text in the evidence panel.</summary>
    Text,
    /// <summary>Files that can run, or carry something that runs, when opened (<see cref="EvidenceRisk"/>).</summary>
    CanRun,
    /// <summary>Files a current timeline entry or the brief cites.</summary>
    Cited,
    /// <summary>Files nothing cites yet.</summary>
    Uncited
}

/// <summary>CAP-25: a sortable column of the Evidence tab's list.</summary>
public enum EvidenceSort
{
    Uploaded,
    Name,
    Size,
    Collected
}

/// <summary>
/// CAP-25: which evidence files the Evidence tab lists, and in what order. The filter text matches a file's name or
/// description (anywhere, ignoring case) or the start of its SHA-256; it stays in the component, never the URL (a file
/// name or a hash can be sensitive, as an indicator is: C7). Chips of one kind widen each other (images or text or
/// can-run; cited or uncited), and the two kinds narrow each other. Ties sort newest upload first, so the order is
/// stable; files with no collection time recorded sort after those with one, whichever way.
/// </summary>
public static class EvidenceListView
{
    /// <summary>The direction a column sorts in first: newest and largest at the top, A–Z for names.</summary>
    public static bool DefaultDescending(EvidenceSort sort) => sort != EvidenceSort.Name;

    private static readonly EvidenceChip[] KindChips = [EvidenceChip.Images, EvidenceChip.Text, EvidenceChip.CanRun];
    private static readonly EvidenceChip[] CitationChips = [EvidenceChip.Cited, EvidenceChip.Uncited];

    /// <param name="isCited">Whether a file is cited (by a current timeline entry or the brief), as the row says.</param>
    public static IReadOnlyList<Domain.Entities.Evidence> Apply(IEnumerable<Domain.Entities.Evidence> items, string? filter,
        IReadOnlySet<EvidenceChip> chips, Func<Domain.Entities.Evidence, bool> isCited, EvidenceSort sort, bool descending)
    {
        var text = filter?.Trim() ?? "";
        var kinds = KindChips.Where(chips.Contains).ToList();
        var citations = CitationChips.Where(chips.Contains).ToList();
        var shown = items.Where(ev => (text.Length == 0 || Matches(ev, text))
                                      && (kinds.Count == 0 || kinds.Any(k => Is(ev, k, isCited)))
                                      && (citations.Count == 0 || citations.Any(k => Is(ev, k, isCited))));
        return Sorted(shown, sort, descending).ToList();
    }

    /// <summary>Whether the filter text matches a file: its name or description, or the start of its hash.</summary>
    public static bool Matches(Domain.Entities.Evidence ev, string text) =>
        ev.OriginalFileName.Contains(text, StringComparison.OrdinalIgnoreCase)
        || (ev.Description?.Contains(text, StringComparison.OrdinalIgnoreCase) ?? false)
        || (text.Length >= 4 && text.All(char.IsAsciiHexDigit) && ev.Sha256.StartsWith(text, StringComparison.OrdinalIgnoreCase));

    /// <summary>Whether a file is of a chip's kind.</summary>
    public static bool Is(Domain.Entities.Evidence ev, EvidenceChip chip, Func<Domain.Entities.Evidence, bool> isCited) => chip switch
    {
        EvidenceChip.Images => ev.ContentType?.StartsWith("image/", StringComparison.OrdinalIgnoreCase) == true,
        EvidenceChip.Text => EvidenceService.IsTextPreviewable(ev.ContentType, ev.OriginalFileName),
        EvidenceChip.CanRun => EvidenceRisk.IsRisky(ev.OriginalFileName, ev.ContentType),
        EvidenceChip.Cited => isCited(ev),
        EvidenceChip.Uncited => !isCited(ev),
        _ => false
    };

    private static IEnumerable<Domain.Entities.Evidence> Sorted(IEnumerable<Domain.Entities.Evidence> items, EvidenceSort sort, bool descending)
    {
        IOrderedEnumerable<Domain.Entities.Evidence> ordered = sort switch
        {
            EvidenceSort.Name => descending
                ? items.OrderByDescending(e => e.OriginalFileName, StringComparer.CurrentCultureIgnoreCase)
                : items.OrderBy(e => e.OriginalFileName, StringComparer.CurrentCultureIgnoreCase),
            EvidenceSort.Size => descending ? items.OrderByDescending(e => e.SizeBytes) : items.OrderBy(e => e.SizeBytes),
            EvidenceSort.Collected => descending
                ? items.OrderBy(e => e.CollectedAtUtc is null).ThenByDescending(e => e.CollectedAtUtc)
                : items.OrderBy(e => e.CollectedAtUtc is null).ThenBy(e => e.CollectedAtUtc),
            _ => descending ? items.OrderByDescending(e => e.CreatedAtUtc) : items.OrderBy(e => e.CreatedAtUtc),
        };
        return ordered.ThenByDescending(e => e.CreatedAtUtc).ThenBy(e => e.Id);
    }
}
