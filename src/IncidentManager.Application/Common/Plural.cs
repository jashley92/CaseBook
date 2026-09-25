namespace IncidentManager.Application.Common;

/// <summary>Counted nouns for user-facing text: "1 case", "3 cases", instead of "3 case(s)".</summary>
public static class Plural
{
    /// <summary>"{n} {noun}" with the noun pluralized unless n is 1. Pass <paramref name="many"/> for irregular plurals.</summary>
    public static string Of(int n, string one, string? many = null) =>
        $"{n} {(n == 1 ? one : many ?? one + "s")}";
}
