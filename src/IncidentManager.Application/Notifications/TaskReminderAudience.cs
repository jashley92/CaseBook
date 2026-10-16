using IncidentManager.Application.Abstractions;
using IncidentManager.Application.ApiTokens;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;

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
}

/// <summary>
/// BUG-377: who a reminder (task, deadline, stale case, digest) may name a case to. The person must still be entitled
/// to it: active, holding a role that grants ViewCases, and for a restricted case able to see it (<see cref="CaseAudience"/>).
/// The user mirror holds the roles from someone's last sign-in, so a leaver or someone moved to another role kept getting
/// case and task titles. Where the directory of record can say (Windows sign-in), its current answer is used; when it
/// can't be reached the mirror stands (WF-57, as BUG-20's feed and REV-50's managers do). One instance per scan: each
/// person is looked up once.
/// </summary>
public sealed class ReminderAudience(IUserDirectory? users, IRoleDirectory? roles, ITokenOwnerCheck? owners = null)
{
    // Null: unknown, or the directory says disabled or gone. Unjudged: nothing to ask (no mirror, directory silent).
    private readonly Dictionary<string, string?> _rolesNow = new(StringComparer.OrdinalIgnoreCase);
    private const string Unjudged = "\0";

    /// <summary>Whether the named roles grant ViewCases. Without a role directory to ask, any role does (as before).</summary>
    public static bool GrantsViewCases(IEnumerable<string> roleNames, IRoleDirectory? roles)
    {
        var names = roleNames.Where(r => !string.IsNullOrWhiteSpace(r)).Select(r => r.Trim()).ToList();
        return roles is null ? names.Count > 0 : roles.PermissionsForRoles(names).Contains(Permission.ViewCases);
    }

    public static bool GrantsViewCases(string? rolesCsv, IRoleDirectory? roles) =>
        GrantsViewCases(IncidentManager.Domain.Common.RoleList.Split(rolesCsv, roles is null ? null : roles.IsRole), roles);   // BUG-591

    /// <summary>Active and holding a role that grants ViewCases.</summary>
    public async Task<bool> EntitledAsync(string? userId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(userId)) return false;
        var csv = await RolesNowAsync(userId, ct);
        return ReferenceEquals(csv, Unjudged) || (csv is not null && GrantsViewCases(csv, roles));
    }

    /// <summary>Entitled, and for a restricted case its IC, on its team, or cleared for restricted cases.</summary>
    public async Task<bool> CanSeeAsync(string? userId, bool isRestricted, string? incidentCommander,
        IReadOnlyCollection<string> team, CancellationToken ct = default)
    {
        if (!await EntitledAsync(userId, ct)) return false;
        if (!isRestricted) return true;
        var csv = await RolesNowAsync(userId!, ct);
        // BUG-96: with no roles to judge clearance by, only the team and the IC.
        if (roles is null || ReferenceEquals(csv, Unjudged))
            return string.Equals(userId, incidentCommander, StringComparison.Ordinal) || team.Contains(userId!, StringComparer.Ordinal);
        return CaseAudience.CanSee(true, incidentCommander, team, new UserSummary(userId!, "", null, null, csv!), roles);
    }

    /// <summary>
    /// The user a task reminder goes to: the owner when they can see the case, else null so it goes to the incident
    /// commander (BUG-96), rather than to nobody and so tried again on every scan.
    /// </summary>
    public async Task<string?> OwnerAsync(bool isRestricted, string? incidentCommander, IReadOnlyCollection<string> team,
        string? owner, CancellationToken ct = default)
    {
        owner = TaskReminderAudience.OwnerId(owner, users);
        if (string.IsNullOrWhiteSpace(owner)) return owner;
        // A free-text owner who isn't a directory user (a vendor contact) can't be judged or emailed; left as written,
        // it falls to the IC when the email is addressed, as before.
        if (!isRestricted && users is not null && users.Resolve(owner) is null) return owner;
        return await CanSeeAsync(owner, isRestricted, incidentCommander, team, ct) ? owner : null;
    }

    /// <summary>The incident commander a reminder may fall back to, or null when they're no longer entitled to the case.</summary>
    public async Task<string?> IncidentCommanderAsync(bool isRestricted, string? incidentCommander,
        IReadOnlyCollection<string> team, CancellationToken ct = default) =>
        string.IsNullOrWhiteSpace(incidentCommander) || await CanSeeAsync(incidentCommander, isRestricted, incidentCommander, team, ct)
            ? incidentCommander : null;

    /// <summary>The recipients still entitled to the case, in order.</summary>
    public async Task<List<string>> EntitledOnlyAsync(IEnumerable<string> userIds, bool isRestricted, string? incidentCommander,
        IReadOnlyCollection<string> team, CancellationToken ct = default)
    {
        var kept = new List<string>();
        foreach (var id in userIds)
            if (await CanSeeAsync(id, isRestricted, incidentCommander, team, ct)) kept.Add(id);
        return kept;
    }

    /// <summary>
    /// BUG-596/597: the people a notification from a user's action (an assignment, an @mention, a handoff) may go to, by
    /// the same rule as the reminders: entitled now, by the directory of record where it can say, and able to see a
    /// restricted case. The instance from DI lives as long as its caller (a circuit, in the UI), so each call looks
    /// people up afresh rather than keep an answer that would outlast someone leaving.
    /// </summary>
    public Task<List<string>> RecipientsAsync(IEnumerable<string> userIds, bool isRestricted, string? incidentCommander,
        IReadOnlyCollection<string> team, CancellationToken ct = default) =>
        new ReminderAudience(users, roles, owners).EntitledOnlyAsync(userIds, isRestricted, incidentCommander, team, ct);

    // The roles a person holds now: those the directory of record maps them to when it answers, else the mirror's.
    private async Task<string?> RolesNowAsync(string userId, CancellationToken ct)
    {
        if (_rolesNow.TryGetValue(userId, out var known)) return known;
        string? csv;
        if (owners is not null && await owners.CheckRecipientAsync(userId, ct) is { } access)
            csv = access.Active ? IncidentManager.Domain.Common.RoleList.Join(access.Roles) : null;
        else if (users is not null)
            csv = users.Resolve(userId)?.RolesCsv;
        else
            csv = Unjudged;
        return _rolesNow[userId] = csv;
    }
}
