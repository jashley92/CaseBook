using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A user mirrored from Active Directory. Roles are resolved from AD group membership at
/// sign-in and cached here for display and assignment pickers. No passwords are ever stored.
/// </summary>
public class AppUser : Entity
{
    /// <summary>AD security identifier &mdash; the stable key.</summary>
    public string Sid { get; set; } = string.Empty;
    public string UserPrincipalName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string? Email { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }

    /// <summary>Comma-separated <see cref="Enums.AppRole"/> names resolved from AD groups.</summary>
    public string RolesCsv { get; set; } = string.Empty;

    /// <summary>
    /// S-12: when this user's current agenda-feed link was issued. A feed token is valid only if it carries exactly this
    /// time (and is under a year old), so resetting the link voids every earlier one for this user alone.
    /// </summary>
    public DateTimeOffset? FeedLinkIssuedAtUtc { get; set; }
}
