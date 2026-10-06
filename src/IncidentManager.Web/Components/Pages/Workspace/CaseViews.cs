using IncidentManager.Application.Compliance;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Web.Components.Pages.Workspace;

/// <summary>
/// RD-11 (RD-27: lifted out of CaseWorkspace): the case's views and their parts. A part's key is the stable routing key
/// (<c>?tab=</c>, chips, counts, flashes, the feed), so a link to "Entities" or "Report" lands on that part; a view's name
/// in <c>?tab=</c> opens the part last used there. RD-08: working notes are the Record's "Working notes" lens
/// (<c>?tab=Notes</c> opens it).
/// </summary>
public static class CaseViews
{
    public static readonly (string View, string[] Parts)[] All =
    [
        ("Record", ["Timeline"]),
        ("Things", ["Entities", "Evidence", "Attack", "Connections", "Impact"]),
        ("Tasks", ["Tasks"]),
        ("Briefing", ["Briefing"]),
        ("Paper", ["Report", "Review", "Audit"]),
    ];

    public static string ViewOf(string part) =>
        part == "Closeout" ? "Close-out" : All.FirstOrDefault(v => v.Parts.Contains(part)).View ?? "Record";

    /// <summary>UX-19: a part's key stays the routing key; this is what the bar and the palette show for it.</summary>
    public static string Label(string part) => part switch
    {
        "Timeline" => "Record",
        "Entities" => "IOCs & entities",
        "Attack" => "ATT&CK",
        "Review" => "Lessons learned",
        "Audit" => "Audit trail",
        _ => part,
    };

    /// <summary>A closed case opens on its Briefing (the outcome leads); an open one on its Record.</summary>
    public static string DefaultPart(Case? c) => c?.Phase == CasePhase.Closed ? "Briefing" : "Timeline";

    /// <summary>The part a <c>?tab=</c> value names: a part, a view (its last-used part), or Notes.</summary>
    public static string? Resolve(string? q, IReadOnlyDictionary<string, string> lastPart)
    {
        if (string.IsNullOrWhiteSpace(q)) return null;
        if (string.Equals(q, "Notes", StringComparison.OrdinalIgnoreCase)) return "Notes";
        foreach (var (view, parts) in All)
        {
            if (parts.FirstOrDefault(p => string.Equals(p, q, StringComparison.OrdinalIgnoreCase)) is { } part) return part;
            if (string.Equals(view, q, StringComparison.OrdinalIgnoreCase)) return lastPart.GetValueOrDefault(view) ?? parts[0];
        }
        return null;
    }
}

/// <summary>
/// RD-27: what the view bar and the parts say about each view and part for one render: counts, the "new" dot from a
/// collaborator's change, quiet (INV-38: the report and lessons stay quiet until they matter, the audit trail always)
/// and the reason a quiet one matters now.
/// </summary>
public sealed record CaseViewFacts(Case Case, CaseNotificationDeadlines? Notify, string ActiveTab, IReadOnlyDictionary<string, int> NewOnTab)
{
    public string ActiveView => CaseViews.ViewOf(ActiveTab);

    // Impact is a Things part from Incident up, or wherever impact has been recorded.
    private bool ImpactMatters => Case.Classification is Classification.Incident or Classification.Breach
        || Case.AffectedIndividualsCount is not null || Case.DataElements.Count > 0 || !string.IsNullOrWhiteSpace(Case.AffectedStates);

    public List<string> PartsShown(string view) =>
        (CaseViews.All.FirstOrDefault(v => v.View == view).Parts ?? []).Where(p => p != "Impact" || ImpactMatters || ActiveTab == "Impact").ToList();

    // Report matters on a breach, while a notification deadline runs, or from Recovery; Lessons learned from Post-Incident.
    private bool ReportMatters => Case.Classification == Classification.Breach || Notify?.Headline is { IsActive: true } || Case.Phase >= CasePhase.Recovery;
    private bool LessonsMatter => Case.Phase >= CasePhase.PostIncident;

    public int? TabCount(string tab)
    {
        var n = tab switch
        {
            "Timeline" => Case.TimelineEntries.Count,
            "Entities" => Case.Entities.Count,
            "Evidence" => Case.Evidence.Count,
            "Tasks" => Case.ActionItems.Count(a => a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled),
            _ => -1
        };
        return n <= 0 ? null : n;
    }

    public bool TabHasNew(string tab) => tab != ActiveTab && NewOnTab.GetValueOrDefault(tab) > 0;

    public bool TabQuiet(string tab) => ActiveTab != tab && tab switch
    {
        "Report" => !ReportMatters,
        "Review" => !LessonsMatter,
        "Audit" => true,
        _ => false
    };

    public string? TabWhy(string tab) => tab switch
    {
        "Report" when Notify?.Headline is { IsActive: true } nh => $"{nh.JurisdictionCode} {nh.WindowHours} h",
        "Review" when Case.Phase == CasePhase.PostIncident => "Next gate",
        _ => null
    };

    // RD-11: a view's count, "new" dot, quiet and why come from its parts.
    public int? ViewCount(string view) => view switch
    {
        "Record" => TabCount("Timeline"),
        "Things" => (TabCount("Entities") ?? 0) + (TabCount("Evidence") ?? 0) is > 0 and var n ? n : null,
        "Tasks" => TabCount("Tasks"),
        _ => null
    };
    public bool ViewHasNew(string view) => view != ActiveView && CaseViews.All.First(v => v.View == view).Parts.Any(TabHasNew);
    public bool ViewQuiet(string view) => view == "Paper" && ActiveView != view && !ReportMatters && !LessonsMatter;
    public string? ViewWhy(string view) => view == "Paper" ? TabWhy("Report") ?? TabWhy("Review") : null;
}
