namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Issues and validates the bearer token that authenticates a user's personal agenda calendar (ICS) feed
/// (E-39). A calendar client (Outlook, etc.) polls the feed URL unauthenticated, so the token in the query
/// string <em>is</em> the credential — it must identify exactly one user and be unforgeable. The token is an
/// HMAC over the user id and an issue time, keyed by a server-only secret. The issue time lets
/// <c>AgendaFeedService</c> expire a link and void one user's earlier links (S-12); rotating the secret
/// still invalidates everyone's at once. The feed is disabled (no token issued, none accepted) until the secret is set.
/// </summary>
public interface IAgendaFeedTokens
{
    /// <summary>Whether a signing secret is configured. When false the feed is off and no token is issued.</summary>
    bool Enabled { get; }

    /// <summary>A feed token for the user, issued at <paramref name="issuedAtUtc"/> (whole seconds); <c>null</c> when disabled.</summary>
    string? Issue(string userId, DateTimeOffset issuedAtUtc);

    /// <summary>Validates a token's signature and yields the user and issue time it carries; false if disabled or invalid.</summary>
    bool TryValidate(string token, out string userId, out DateTimeOffset issuedAtUtc);
}
