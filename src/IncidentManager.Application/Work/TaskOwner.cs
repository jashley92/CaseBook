using IncidentManager.Application.Abstractions;

namespace IncidentManager.Application.Work;

/// <summary>
/// A task's <c>Owner</c> is free text: a user id, a UPN, an email, a display name, or a template's owner hint. It belongs
/// to someone when it matches any of their identifiers, ignoring case and surrounding spaces. My Work, the agenda and a
/// case hand-off (REV-17) all read "mine" this way, so they agree on which tasks are someone's.
/// </summary>
public static class TaskOwner
{
    /// <summary>Whether the free-text owner is the current user.</summary>
    public static bool IsMine(string? owner, ICurrentUser user) =>
        Matches(owner, [user.UserId, user.UserPrincipalName, user.DisplayName, user.Email]);

    /// <summary>Whether the free-text owner is any of the given identifiers (blank ones are ignored).</summary>
    public static bool Matches(string? owner, IEnumerable<string?> identifiers)
    {
        if (string.IsNullOrWhiteSpace(owner)) return false;
        var o = owner.Trim();
        return identifiers.Any(id => !string.IsNullOrWhiteSpace(id) && string.Equals(o, id.Trim(), StringComparison.OrdinalIgnoreCase));
    }
}
