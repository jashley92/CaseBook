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

    /// <summary>
    /// CAP-09 review: the API token a request signed in with (its row id, never the secret), set only by the API-token
    /// scheme. <see cref="System.Security.Claims.ClaimTypes.NameIdentifier"/> is the token's owner, which every personal
    /// token of one user shares, so a limit kept per token is partitioned on this.
    /// </summary>
    public const string ApiTokenId = "casebook:api_token_id";
}
