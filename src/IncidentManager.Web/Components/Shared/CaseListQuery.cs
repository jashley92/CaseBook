using IncidentManager.Application.Cases;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Web.Components.Shared;

/// <summary>
/// CAP-17 (C2): the Cases page's URL filter read into a <see cref="CaseFilter"/>, by the page for its list and by
/// <c>/export/cases.csv</c> for the file, so the export lists exactly the cases the page does. Everything but the page
/// position and size, which the export pages through itself. C16: enums by name only; a bad value is ignored, not an error.
/// </summary>
public static class CaseListQuery
{
    /// <summary>The <c>sort</c> values, by column.</summary>
    public static readonly IReadOnlyDictionary<CaseSort, string> SortKeys = new Dictionary<CaseSort, string>
    {
        [CaseSort.Opened] = "opened", [CaseSort.Updated] = "updated", [CaseSort.Severity] = "severity",
        [CaseSort.Sla] = "sla", [CaseSort.Phase] = "phase", [CaseSort.CaseNumber] = "case",
    };

    /// <summary>The filter a query names. <paramref name="get"/> reads one parameter (null when it isn't there).</summary>
    public static CaseFilter Parse(Func<string, string?> get)
    {
        var filter = new CaseFilter
        {
            OnlyMine = string.Equals(get("scope"), "mine", StringComparison.OrdinalIgnoreCase),
            Classification = EnumNames.OrNull<Classification>(get("classification")),
            Phase = EnumNames.OrNull<CasePhase>(get("phase")),
            MinSeverity = EnumNames.OrNull<Severity>(get("sev")),
            Origin = EnumNames.OrNull<CaseOrigin>(get("origin")),
            OutcomeKey = string.IsNullOrEmpty(get("outcome")) ? null : get("outcome"),
            Search = get("q") ?? "",
            IncludeClosed = QueryValue.Flag(get("closed")),
            IncludeExercises = QueryValue.Flag(get("exercises")),
            OverdueOnly = QueryValue.Flag(get("overdue")),
            SlaAtRiskOnly = QueryValue.Flag(get("sla")),
            NotifyDeadlineOnly = QueryValue.Flag(get("notify")),
            ReferredOnly = QueryValue.Flag(get("referred")),
            OnHoldOnly = QueryValue.Flag(get("hold")),
        };
        var assignee = string.IsNullOrWhiteSpace(get("assignee")) ? null : get("assignee");
        filter.UnassignedOnly = assignee == "none";
        filter.AssigneeUserId = assignee == "none" ? null : assignee;

        // opened=YYYY-MM: BUG-475, read invariantly (the key is always Gregorian yyyy-MM), and a month the list can't
        // bound (years 1 and 9999) is ignored like any other bad value.
        if (OpenedMonth(get("opened")) is { } mo)
        {
            filter.OpenedYear = mo.Year;
            filter.OpenedMonth = mo.Month;
        }

        filter.Sort = SortKeys.FirstOrDefault(k => string.Equals(k.Value, get("sort"), StringComparison.OrdinalIgnoreCase)).Key;
        filter.SortDescending = get("dir") is "asc" ? false : get("dir") is "desc" ? true : CaseSorts.DefaultDescending(filter.Sort);
        return filter;
    }

    /// <summary>The page's own query parameters, as it writes them.</summary>
    public static CaseFilter Parse(IReadOnlyDictionary<string, object?> query) =>
        Parse(k => query.TryGetValue(k, out var v) ? v?.ToString() : null);

    /// <summary>The month an <c>opened=</c> value names, or null when it names none the list can bound.</summary>
    public static DateTime? OpenedMonth(string? raw) =>
        !string.IsNullOrWhiteSpace(raw)
        && DateTime.TryParse($"{raw}-01", System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.None, out var mo)
        && mo.Year is >= 2 and <= 9998
            ? mo : null;

    /// <summary>Copies every filter (not the page position or size) from <paramref name="from"/> onto <paramref name="to"/>.</summary>
    public static void CopyFilters(CaseFilter from, CaseFilter to)
    {
        to.OnlyMine = from.OnlyMine;
        to.Classification = from.Classification;
        to.Phase = from.Phase;
        to.MinSeverity = from.MinSeverity;
        to.Origin = from.Origin;
        to.OutcomeKey = from.OutcomeKey;
        to.Search = from.Search;
        to.IncludeClosed = from.IncludeClosed;
        to.IncludeExercises = from.IncludeExercises;
        to.OverdueOnly = from.OverdueOnly;
        to.SlaAtRiskOnly = from.SlaAtRiskOnly;
        to.NotifyDeadlineOnly = from.NotifyDeadlineOnly;
        to.ReferredOnly = from.ReferredOnly;
        to.OnHoldOnly = from.OnHoldOnly;
        to.UnassignedOnly = from.UnassignedOnly;
        to.AssigneeUserId = from.AssigneeUserId;
        to.OpenedYear = from.OpenedYear;
        to.OpenedMonth = from.OpenedMonth;
        to.Sort = from.Sort;
        to.SortDescending = from.SortDescending;
    }
}
