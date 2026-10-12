using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;

namespace IncidentManager.Application.Notifications;

/// <summary>
/// BUG-96: a task reminder names the case and the task, so on a restricted case it goes to the task's owner only if
/// they can see the case (on its team, its incident commander, or cleared for restricted cases). Otherwise it goes to
/// the incident commander, as for a task with no owner; someone taken off the team stops hearing about its tasks.
/// </summary>
public static class TaskReminderAudience
{
    public static string? Owner(bool isRestricted, string? incidentCommander, IReadOnlyCollection<string> team,
        string? owner, IUserDirectory? users, IRoleDirectory? roles)
    {
        if (!isRestricted || string.IsNullOrWhiteSpace(owner)) return owner;
        if (string.Equals(owner, incidentCommander, StringComparison.Ordinal) || team.Contains(owner, StringComparer.Ordinal))
            return owner;
        // Off the team: only someone cleared for restricted cases still sees it.
        return users is not null && roles is not null && CaseAudience.CanSee(true, incidentCommander, team, users.Resolve(owner), roles)
            ? owner : null;
    }
}
