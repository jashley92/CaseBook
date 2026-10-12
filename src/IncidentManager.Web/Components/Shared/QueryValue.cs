namespace IncidentManager.Web.Components.Shared;

/// <summary>
/// BUG-31: query-string values read from the raw string. A typed <c>[SupplyParameterFromQuery]</c> (bool, int, Guid)
/// throws on a value it can't parse, so a hand-edited or clipped link (<c>?closed=1</c>, <c>?page=x</c>, half a guid)
/// broke the page instead of being ignored.
/// </summary>
public static class QueryValue
{
    /// <summary>On for "true", "1", "yes" or "on" (any case); anything else, or nothing, is off.</summary>
    public static bool Flag(string? raw) =>
        raw?.Trim().ToLowerInvariant() is "true" or "1" or "yes" or "on";

    public static int? Int(string? raw) =>
        int.TryParse(raw, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var n) ? n : null;

    public static Guid? Id(string? raw) => Guid.TryParse(raw, out var g) ? g : null;
}
