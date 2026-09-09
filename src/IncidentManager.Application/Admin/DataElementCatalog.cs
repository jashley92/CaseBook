namespace IncidentManager.Application.Admin;

/// <summary>
/// The built-in <b>data-element</b> reference set (X-03) seeded on first run — a starting baseline of the
/// personal-data categories a NY P&amp;C / Flood / Auto insurer tracks. After seeding, elements are
/// admin-managed reference data (rename / reorder / archive / add). Each element's stable identity is its
/// <see cref="Seed.Key"/> — the value a case stores and the tamper-evident canonical hashes, exactly like the
/// X-02 taxonomy layer stores a stable member name and varies only the display label.
/// </summary>
public static class DataElementCatalog
{
    /// <summary>One seeded element: a stable machine key (the identity), a default label, and a display order.</summary>
    public sealed record Seed(string Key, string Label, int SortOrder);

    /// <summary>The thirteen elements, in their default display order.</summary>
    public static readonly IReadOnlyList<Seed> Defaults =
    [
        new("Name",                   "Name",                          1),
        new("SocialSecurityNumber",   "Social Security number",        2),
        new("DriverLicenseOrStateId", "Driver's license / state ID",   3),
        new("FinancialAccountNumber", "Financial account number",      4),
        new("PaymentCard",            "Payment card",                  5),
        new("DateOfBirth",            "Date of birth",                 6),
        new("ClaimsData",             "Claims data",                   7),
        new("PolicyData",             "Policy data",                   8),
        new("PropertyOrFloodAddress", "Property / flood address",      9),
        new("MedicalOrHealthInfo",    "Medical / health information", 10),
        new("EmailAddress",           "Email address",                11),
        new("OnlineCredentials",      "Online credentials",           12),
        new("BiometricData",          "Biometric data",               13),
    ];
}
