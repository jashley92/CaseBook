using IncidentManager.Application.Admin;

namespace IncidentManager.Web.Components.Shared;

/// <summary>
/// CAP-36: the detection source a case's pages name and link to. A case's team's own label and link template when the team
/// sets them, else the organization's (<c>ExternalLinks:DetectionSourceLabel</c>, <c>ExternalLinks:DetectionCaseUrlTemplate</c>),
/// else "SIEM" and no link: one rule for the workspace, its tabs and the New case form.
/// </summary>
public static class DetectionSource
{
    /// <summary>The detection system's name for a case of <paramref name="team"/> (null: no team).</summary>
    public static string Label(IConfiguration config, TeamView? team)
    {
        if (!string.IsNullOrWhiteSpace(team?.DetectionSourceLabel)) return team.DetectionSourceLabel.Trim();
        var label = config["ExternalLinks:DetectionSourceLabel"];
        return string.IsNullOrWhiteSpace(label) ? "SIEM" : label;
    }

    /// <summary>The link to <paramref name="detectionCaseId"/> in the detection system, or null (no template, no id).</summary>
    public static string? CaseUrl(IConfiguration config, TeamView? team, string? detectionCaseId)
    {
        var template = string.IsNullOrWhiteSpace(team?.DetectionLinkTemplate) ? config["ExternalLinks:DetectionCaseUrlTemplate"] : team.DetectionLinkTemplate;
        if (string.IsNullOrWhiteSpace(template) || string.IsNullOrWhiteSpace(detectionCaseId)) return null;
        return Application.Content.LinkTemplate.Fill(template, detectionCaseId);   // BUG-264
    }
}
