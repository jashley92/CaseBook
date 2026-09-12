using IncidentManager.Application.Admin;

namespace IncidentManager.Web.Components.Pages.CaseTabs;

/// <summary>
/// Report-tab UI state that must outlive the tab's re-mount (UX-13). The case workspace keys its tab body
/// by the active tab, so the extracted tab is recreated on each switch. Holding these here, in the parent,
/// keeps the "Preview" panel open across tab switches (as it was when the flag lived on the parent) and
/// caches the profile list so it isn't re-fetched on every visit. The profile <em>selection</em> is not
/// kept here: like today, it re-seeds from the case's saved profile each time the tab is opened.
/// </summary>
public sealed class CaseReportState
{
    public bool ShowPreview { get; set; }
    public IReadOnlyList<ReportProfileView>? Profiles { get; set; }
}
