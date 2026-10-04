namespace IncidentManager.Application.Admin;

/// <summary>
/// HR-01: the built-in case outcomes seeded on first run. After seeding they're admin-managed reference data
/// (relabel, describe, reorder, archive, add more). Each one's identity is its stable <see cref="Seed.Key"/>, the
/// value a case stores. Wording is deliberately neutral (discovery-conscious records).
/// </summary>
public static class CaseOutcomeCatalog
{
    /// <summary>One seeded outcome: stable key, default label, one-line description, display order.</summary>
    public sealed record Seed(string Key, string Label, string Description, int SortOrder);

    public const string Confirmed = "Confirmed";
    public const string PolicyViolation = "PolicyViolation";
    public const string BenignOrExpected = "BenignOrExpected";
    public const string FalsePositive = "FalsePositive";
    public const string Inconclusive = "Inconclusive";
    public const string Duplicate = "Duplicate";

    /// <summary>A built-in outcome's default label, or the key itself; for when the admin-managed labels aren't at hand.</summary>
    public static string Label(string key) => Defaults.FirstOrDefault(d => d.Key == key)?.Label ?? key;

    public static readonly IReadOnlyList<Seed> Defaults =
    [
        new(Confirmed,        "Confirmed",          "The reported activity happened.",                              1),
        new(PolicyViolation,  "Policy violation",   "An authorized person acted against policy.",                  2),
        new(BenignOrExpected, "Benign or expected", "The activity was authorized or normal.",                       3),
        new(FalsePositive,    "False positive",     "The detection itself was wrong.",                              4),
        new(Inconclusive,     "Inconclusive",       "The team couldn't determine what happened.",                   5),
        new(Duplicate,        "Duplicate",          "Covered by another case.",                                      6),
    ];
}
