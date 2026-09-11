namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Issues and validates the bearer token that authenticates a user's personal agenda calendar (ICS) feed
/// (E-39). A calendar client (Outlook, etc.) polls the feed URL unauthenticated, so the token in the query
/// string <em>is</em> the credential — it must identify exactly one user and be unforgeable. The token is a
/// stateless HMAC over the user id keyed by a server-only secret, so it carries no per-user storage and no
/// migration; rotating the secret invalidates every issued token at once (the feed's only revocation lever).
/// The feed is disabled (no token issued, none accepted) until the secret is configured.
/// </summary>
public interface IAgendaFeedTokens
{
    /// <summary>Whether a signing secret is configured. When false the feed is off and no token is issued.</summary>
    bool Enabled { get; }

    /// <summary>A feed token for the user, or <c>null</c> when the feed is disabled.</summary>
    string? Issue(string userId);

    /// <summary>Validates a token and yields the user id it was issued for; false if disabled or invalid.</summary>
    bool TryValidate(string token, out string userId);
}
