using System.Security.Cryptography;
using System.Text;
using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Agenda;

/// <summary>
/// Stateless HMAC-SHA256 implementation of <see cref="IAgendaFeedTokens"/> (E-39). Token format is
/// <c>{base64url(userId)}.{base64url(HMAC(secret, userId))}</c>; validation recomputes the MAC and compares
/// it in constant time, so a token cannot be forged or edited to name another user without the secret. The
/// secret is read from <c>Agenda:FeedKey</c> (server-side config only — never admin-editable, like the seal
/// signing key); a blank secret disables the feed. Signing/verification is per-call and cheap, so a singleton
/// is fine even though config can change under it.
/// </summary>
public sealed class AgendaFeedTokenService : IAgendaFeedTokens
{
    private readonly IConfiguration _config;

    public AgendaFeedTokenService(IConfiguration config) => _config = config;

    private string? Secret
    {
        get
        {
            var s = _config["Agenda:FeedKey"];
            return string.IsNullOrWhiteSpace(s) ? null : s;
        }
    }

    public bool Enabled => Secret is not null;

    public string? Issue(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId) || Secret is not { } secret) return null;
        var id = userId.Trim();
        return $"{B64(Encoding.UTF8.GetBytes(id))}.{B64(Mac(secret, id))}";
    }

    public bool TryValidate(string token, out string userId)
    {
        userId = "";
        if (string.IsNullOrWhiteSpace(token) || Secret is not { } secret) return false;

        var dot = token.IndexOf('.');
        if (dot <= 0 || dot == token.Length - 1) return false;

        byte[] idBytes, macBytes;
        try
        {
            idBytes = FromB64(token[..dot]);
            macBytes = FromB64(token[(dot + 1)..]);
        }
        catch (FormatException) { return false; }

        var id = Encoding.UTF8.GetString(idBytes);
        var expected = Mac(secret, id);
        if (!CryptographicOperations.FixedTimeEquals(macBytes, expected)) return false;

        userId = id;
        return true;
    }

    private static byte[] Mac(string secret, string message) =>
        HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(message));

    // URL-safe base64 without padding, so the token drops cleanly into a query string.
    private static string B64(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromB64(string s)
    {
        var b = s.Replace('-', '+').Replace('_', '/');
        b = (b.Length % 4) switch { 2 => b + "==", 3 => b + "=", _ => b };
        return Convert.FromBase64String(b);
    }
}
