namespace IncidentManager.Application.Reporting;

/// <summary>
/// The toggleable, reorderable body sections of a case report, in default print order. Identity is the
/// enum name (the persisted token), so sections can be reordered/hidden without breaking stored layouts.
/// The document title, header/footer and the integrity provenance stamp are always rendered and are not
/// part of this set.
/// </summary>
public enum ReportSection
{
    Summary,
    BusinessImpact,
    EventTimeline,
    InvestigationTimeline,
    SystemsReviewed,
    Recommendations,
    Outcome,
    Appendix
}

/// <summary>One section with its display order position and whether it is included.</summary>
public sealed record ReportSectionState(ReportSection Section, bool Enabled);

/// <summary>
/// Parses and renders the persisted <see cref="ReportingOptions.SectionLayout"/> string. Tolerant by
/// design: unknown tokens are dropped and any section missing from the stored value is appended
/// (enabled) in enum order, so a layout saved before a new section existed still shows it after upgrade.
/// </summary>
public static class ReportLayout
{
    private static readonly ReportSection[] All = Enum.GetValues<ReportSection>();

    /// <summary>Full ordered layout (every section, with its enabled flag) for the admin editor.</summary>
    public static IReadOnlyList<ReportSectionState> Parse(string? raw)
    {
        var seen = new HashSet<ReportSection>();
        var result = new List<ReportSectionState>();

        foreach (var tokenRaw in (raw ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var enabled = !tokenRaw.StartsWith('!');
            var token = enabled ? tokenRaw : tokenRaw[1..].Trim();
            if (Enum.TryParse<ReportSection>(token, ignoreCase: true, out var section) && seen.Add(section))
                result.Add(new ReportSectionState(section, enabled));
        }

        // Append any sections not present in the stored value (new sections, or a blank layout) enabled.
        foreach (var s in All)
            if (seen.Add(s))
                result.Add(new ReportSectionState(s, true));

        return result;
    }

    /// <summary>The enabled sections in print order — what the generators iterate.</summary>
    public static IReadOnlyList<ReportSection> Resolve(string? raw) =>
        Parse(raw).Where(s => s.Enabled).Select(s => s.Section).ToList();

    /// <summary>Serialises an ordered layout back to the persisted token string.</summary>
    public static string Serialize(IEnumerable<ReportSectionState> layout) =>
        string.Join(",", layout.Select(s => s.Enabled ? s.Section.ToString() : "!" + s.Section));
}
