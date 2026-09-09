namespace IncidentManager.Infrastructure.Siem;

/// <summary>
/// Validates the configured SIEM webhook endpoint before anything is sent to it (S-06). The webhook
/// carries the bearer <c>Token</c> and a stream of security events, so egress must be confidential and
/// to a real destination: HTTPS is required, and plain HTTP is permitted only to loopback (a local dev
/// collector) so the token is never sent in cleartext off-box. Any other scheme (or a malformed URL) is
/// refused, which also removes the arbitrary-scheme / non-HTTP SSRF surface.
/// </summary>
public static class SiemWebhookUrl
{
    public static bool IsAcceptable(string? url, out string reason)
    {
        reason = "";
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            reason = "not an absolute URL";
            return false;
        }

        if (uri.Scheme == Uri.UriSchemeHttps) return true;

        // Plain HTTP only to loopback — a local dev/test receiver. Never send the token cleartext off-box.
        if (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback) return true;

        reason = uri.Scheme == Uri.UriSchemeHttp
            ? "http is only permitted to loopback; a remote collector must use https so the token is not sent in cleartext"
            : $"unsupported scheme '{uri.Scheme}' (only https, or http to loopback, is allowed)";
        return false;
    }
}
