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
    /// <summary>
    /// WF-19: a task owner is free text, so one written as an email or UPN (an import, the "External / other" field) is
    /// read as the directory user it names, and reminded, rather than falling to the incident commander. Only email and
    /// UPN, which name one person (owner's decision); a display name, which two people can share, still falls back.
    /// </summary>
    public static string? OwnerId(string? owner, IUserDirectory? users)
    {
        if (users is null || string.IsNullOrWhiteSpace(owner) || users.Resolve(owner) is not null) return owner;
        var o = owner.Trim();
        var named = users.All().Where(u => string.Equals(u.Email?.Trim(), o, StringComparison.OrdinalIgnoreCase)
                                           || string.Equals(u.UserPrincipalName?.Trim(), o, StringComparison.OrdinalIgnoreCase))
            .Select(u => u.UserId).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return named.Count == 1 ? named[0] : owner;
    }

    public static string? Owner(bool isRestricted, string? incidentCommander, IReadOnlyCollection<string> team,
        string? owner, IUserDirectory? users, IRoleDirectory? roles)
    {
        owner = OwnerId(owner, users);
        if (!isRestricted || string.IsNullOrWhiteSpace(owner)) return owner;
        if (string.Equals(owner, incidentCommander, StringComparison.Ordinal) || team.Contains(owner, StringComparer.Ordinal))
            return owner;
        // Off the team: only someone cleared for restricted cases still sees it.
        return users is not null && roles is not null && CaseAudience.CanSee(true, incidentCommander, team, users.Resolve(owner), roles)
            ? owner : null;
    }
}
