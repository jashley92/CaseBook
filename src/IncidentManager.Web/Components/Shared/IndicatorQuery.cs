using System.Globalization;
using IncidentManager.Application.Intel;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Web.Components.Shared;

/// <summary>
/// CAP-27 (C2): the Indicators page's filter, as the page builds it from its controls and as <c>/export/indicators.csv</c>
/// reads it back from the link, through the same function, so the file holds exactly the indicators the page lists. The
/// search is never a link parameter (C7: indicator values stay out of URLs): the page holds it for the person under an
/// opaque reference (<c>ExportSearchRefs</c>, CAP-17) and the link carries <c>qref</c>. C16: enums by name only; a bad
/// value is ignored, not an error.
/// </summary>
public static class IndicatorQuery
{
    /// <summary>The type picker's keys: "ioc" (the default), "all", or one entity type by name.</summary>
    public const string Indicators = "ioc", AllTypes = "all";

    /// <summary>The filter the page's controls describe.</summary>
    public static IndicatorFilter Filter(string? search, string? typeKey, EntityDisposition? verdict, bool sharedOnly, bool includeExercises)
    {
        var (scope, type) = typeKey switch
        {
            null or "" or Indicators => (IndicatorTypeScope.Indicators, (EntityType?)null),
            AllTypes => (IndicatorTypeScope.AllTypes, null),
            var k => EnumNames.OrNull<EntityType>(k) is { } t ? (IndicatorTypeScope.AllTypes, t) : (IndicatorTypeScope.Indicators, null),
        };
        return new IndicatorFilter(search, scope, type, sharedOnly, verdict, includeExercises);
    }

    /// <summary>The export link for <paramref name="filter"/>; <paramref name="searchRef"/> stands for its search.</summary>
    public static string ExportHref(IndicatorFilter filter, string? searchRef)
    {
        var qs = new List<string>();
        var type = filter.Type is { } t ? t.ToString() : filter.Scope == IndicatorTypeScope.AllTypes ? AllTypes : null;
        if (type is not null) qs.Add("type=" + type);
        if (filter.Disposition is { } d) qs.Add("verdict=" + d);
        if (filter.SharedOnly) qs.Add("shared=true");
        if (filter.IncludeExercises) qs.Add("exercises=true");
        if (!string.IsNullOrEmpty(searchRef)) qs.Add("qref=" + Uri.EscapeDataString(searchRef));
        return qs.Count == 0 ? "export/indicators.csv" : "export/indicators.csv?" + string.Join("&", qs);
    }

    /// <summary>The filter an export link names; <paramref name="search"/> is the text its <c>qref</c> stands for.</summary>
    public static IndicatorFilter Parse(Func<string, string?> get, string? search) =>
        Filter(search, get("type"), EnumNames.OrNull<EntityDisposition>(get("verdict")),
            QueryValue.Flag(get("shared")), QueryValue.Flag(get("exercises")));

    /// <summary>"Indicators 301–600 of 1,234": where the page shown sits among the matches when it was read.</summary>
    public static string PageRange(IndicatorLibrary library) =>
        library.Rows.Count == 0
            ? string.Create(CultureInfo.CurrentCulture, $"No more indicators ({library.Matched:N0} match)")
            : string.Create(CultureInfo.CurrentCulture,
                $"Indicators {library.FirstIndex + 1:N0}–{library.FirstIndex + library.Rows.Count:N0} of {library.Matched:N0}");
}
