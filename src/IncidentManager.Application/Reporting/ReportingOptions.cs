namespace IncidentManager.Application.Reporting;

/// <summary>
/// Operational options for the report approval workflow (E-15), bound to the "Reporting" configuration
/// section and administrable in-app via the settings catalog.
/// </summary>
public sealed class ReportingOptions
{
    /// <summary>
    /// When true, a report must be approved by someone <b>other</b> than the analyst who generated it
    /// (two-person / maker-checker control). Off by default so small teams aren't blocked; the approver
    /// is recorded in the audit trail either way.
    /// </summary>
    public bool RequireSeparateApprover { get; set; }

    /// <summary>
    /// Organisation name printed in the report header (the "[Company Name]" line of the house template).
    /// Blank falls back to a bracketed placeholder so an unconfigured deployment is obvious. Kept out of
    /// source and set per-deployment in the admin console so the tenant is never hardcoded.
    /// </summary>
    public string? OrganizationName { get; set; }

    /// <summary>
    /// Team name printed under the organisation name in the report header (the "[Team Name]" line).
    /// Blank falls back to a bracketed placeholder.
    /// </summary>
    public string? TeamName { get; set; }

    /// <summary>
    /// The report body section layout — a comma-separated list of <see cref="ReportSection"/> tokens in
    /// print order, each optionally prefixed with '!' to hide it (e.g. "Summary,!Outcome,Appendix").
    /// Parsed by <see cref="ReportLayout"/>, which is tolerant of unknown/missing tokens so the default
    /// (all sections, enum order) applies when blank and new sections appear enabled after an upgrade.
    /// </summary>
    public string? SectionLayout { get; set; }
}
