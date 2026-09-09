namespace IncidentManager.Application.Security;

/// <summary>Custom claim types the application issues and authorizes against.</summary>
public static class AppClaimTypes
{
    /// <summary>
    /// A single <see cref="Domain.Enums.Permission"/> the user holds. Emitted during authentication by
    /// expanding the user's roles to their permission union; policies authorize on these claims so the
    /// authorization surface is permission-based (roles are just the admin-facing bundling).
    /// </summary>
    public const string Permission = "perm";
}
