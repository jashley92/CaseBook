namespace IncidentManager.Web.Components.Pages.CaseTabs;

/// <summary>
/// Audit-tab UI state that must outlive the tab's re-mount (UX-13). The case workspace keys its tab body
/// by the active tab, so an extracted tab component is recreated on every tab switch — holding the filter
/// selections (and the fetched facet lists) here, in the parent, and passing this object in, means the
/// analyst's audit filters persist across tab switches instead of resetting each visit.
/// </summary>
public sealed class CaseAuditFilter
{
    // Filter selections (bound by the tab's controls).
    public string Actor { get; set; } = "";
    public string Action { get; set; } = "";
    public string Entity { get; set; } = "";
    public DateTime? From { get; set; }
    public DateTime? To { get; set; }

    // Facet lists for the Actor / Entity dropdowns, fetched once per case and cached here.
    public IReadOnlyList<string> Actors { get; set; } = [];
    public IReadOnlyList<string> EntityTypes { get; set; } = [];
    public bool FacetsLoaded { get; set; }
}
