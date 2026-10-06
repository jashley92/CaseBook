using IncidentManager.Domain.Entities;

namespace IncidentManager.Web.Components.Pages.Workspace;

/// <summary>
/// RD-27: what the signed-in user may do on the open case, evaluated by the workspace from the live auth state and
/// handed to its regions, so each region shows only what the user can do (the services enforce it regardless).
/// </summary>
public sealed record CaseAccess(
    bool CanEdit, bool CanReclassify, bool CanManageLegal, bool CanAdmin, bool CanViewAll, bool CanViewRestricted, string MyId)
{
    public static readonly CaseAccess None = new(false, false, false, false, false, false, "");

    public bool CanAnyAction => CanEdit || CanReclassify || CanManageLegal || CanAdmin;

    /// <summary>The IC or a cleared role may lift a restriction (mirrors CaseRestrictionPolicy.CanLift).</summary>
    public bool CanLiftRestriction(Case? c) => CanViewAll || CanViewRestricted
        || (c is not null && string.Equals(c.IncidentCommander, MyId, StringComparison.Ordinal));

    /// <summary>Whether the user is on the case's team.</summary>
    public bool IsOnCase(Case c) => c.Assignments.Any(a => string.Equals(a.UserId, MyId, StringComparison.OrdinalIgnoreCase));
}

/// <summary>RD-27: words the workspace's regions share.</summary>
public static class WorkspaceText
{
    public const string PermissionLost =
        "You no longer have permission to do that. Your access to this case may have changed. Reload the page to see what you can do.";
}

/// <summary>RD-27: where a case goes next, as the header, the palette and the dialogs read it.</summary>
public static class CaseFlow
{
    /// <summary>The phase after the case's current one, or null when it's closed.</summary>
    public static IncidentManager.Domain.Enums.CasePhase? NextPhase(Case? c)
    {
        if (c is null) return null;
        var phases = Enum.GetValues<IncidentManager.Domain.Enums.CasePhase>();
        var i = Array.IndexOf(phases, c.Phase);
        return i >= 0 && i < phases.Length - 1 ? phases[i + 1] : null;
    }
}
