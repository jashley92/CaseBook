namespace IncidentManager.Web.Services;

/// <summary>
/// Composes the verb phrase for a live-collaboration toast (U-30), e.g. "added a timeline entry",
/// "added 2 evidence items", "added a note and 3 entities". Pure and side-effect-free so it can be
/// unit-tested; the caller prefixes the actor's display name.
/// </summary>
public static class ActivityToast
{
    public static string Compose(IEnumerable<string> itemKinds)
    {
        var groups = itemKinds
            .GroupBy(k => k)
            .Select(g => Quantify(g.Key, g.Count()))
            .ToList();
        return "added " + JoinNatural(groups);
    }

    private static string Quantify(string kind, int n) =>
        n == 1 ? $"a {kind}" : $"{n} {Pluralize(kind)}";

    private static string Pluralize(string kind) => kind switch
    {
        "entity" => "entities",
        _ => kind + "s"
    };

    private static string JoinNatural(IReadOnlyList<string> parts) => parts.Count switch
    {
        0 => "changes",
        1 => parts[0],
        2 => $"{parts[0]} and {parts[1]}",
        _ => string.Join(", ", parts.Take(parts.Count - 1)) + $", and {parts[^1]}"
    };
}
