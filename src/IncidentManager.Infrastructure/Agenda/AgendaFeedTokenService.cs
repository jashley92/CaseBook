using System.Security.Cryptography;
using System.Text;
using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Agenda;

/// <summary>
/// HMAC-SHA256 implementation of <see cref="IAgendaFeedTokens"/> (E-39, S-12). Token format is
/// <c>{base64url(userId)}.{unixSeconds}.{base64url(HMAC(secret, userId + "\n" + unixSeconds))}</c>; validation
/// recomputes the MAC and compares it in constant time, so a token can't be forged or edited to name another user or
/// another issue time without the secret. Whether that issue time is still the user's current one is checked by
/// <c>AgendaFeedService</c>. The
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

    public string? Issue(string userId, DateTimeOffset issuedAtUtc)
    {
        if (string.IsNullOrWhiteSpace(userId) || Secret is not { } secret) return null;
        var id = userId.Trim();
        var at = issuedAtUtc.ToUnixTimeSeconds();
        return $"{B64(Encoding.UTF8.GetBytes(id))}.{at}.{B64(Mac(secret, Message(id, at)))}";
    }

    public bool TryValidate(string token, out string userId, out DateTimeOffset issuedAtUtc)
    {
        userId = "";
        issuedAtUtc = default;
        if (string.IsNullOrWhiteSpace(token) || Secret is not { } secret) return false;

        var parts = token.Split('.');
        if (parts.Length != 3 || !long.TryParse(parts[1], System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var at)) return false;

        byte[] idBytes, macBytes;
        try
        {
            idBytes = FromB64(parts[0]);
            macBytes = FromB64(parts[2]);
        }
        catch (FormatException) { return false; }

        var id = Encoding.UTF8.GetString(idBytes);
        if (!CryptographicOperations.FixedTimeEquals(macBytes, Mac(secret, Message(id, at)))) return false;

        try { issuedAtUtc = DateTimeOffset.FromUnixTimeSeconds(at); }
        catch (ArgumentOutOfRangeException) { return false; }
        userId = id;
        return true;
    }

    private static string Message(string id, long at) => $"{id}\n{at}";

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
