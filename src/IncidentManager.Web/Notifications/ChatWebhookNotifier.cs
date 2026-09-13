using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Siem;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.Notifications;

/// <summary>
/// Posts case-lifecycle notifications to a Slack/Teams incoming webhook (PROD-02): a broadcast to a shared
/// SOC channel alongside the per-recipient email path. Mirrors the SIEM <c>WebhookTransport</c> — best-effort,
/// time-bounded, bounded retry, https-only egress (the webhook URL carries the channel secret) — and lives in
/// Web because it needs <see cref="IHttpClientFactory"/>. The URL is resolved through <see cref="ISecretProvider"/>
/// so it may be a literal or a <c>@cyberark:</c> reference (F-19). Never throws into the caller.
/// </summary>
public sealed class ChatWebhookNotifier : IChatNotifier
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly IOptionsMonitor<ChatOptions> _options;
    private readonly ISecretProvider _secrets;
    private readonly ILogger<ChatWebhookNotifier> _logger;

    public ChatWebhookNotifier(IHttpClientFactory httpFactory, IOptionsMonitor<ChatOptions> options,
        ISecretProvider secrets, ILogger<ChatWebhookNotifier> logger)
    {
        _httpFactory = httpFactory;
        _options = options;
        _secrets = secrets;
        _logger = logger;
    }

    public bool Enabled
    {
        get
        {
            var o = _options.CurrentValue;
            return o.Enabled && !string.IsNullOrWhiteSpace(o.WebhookUrl);
        }
    }

    public async Task SendAsync(ChatNotification message, CancellationToken ct = default)
    {
        var o = _options.CurrentValue;
        if (!o.Enabled || string.IsNullOrWhiteSpace(o.WebhookUrl)) return;

        // The webhook URL is itself the channel credential; resolve it (literal or @cyberark: reference).
        var url = await _secrets.ResolveAsync(o.WebhookUrl, ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(url))
        {
            _logger.LogWarning("Chat webhook URL could not be resolved; message not posted.");
            return;
        }

        // Same egress guard as the SIEM webhook (S-06): https required (http only to loopback) so the secret
        // URL is never sent in cleartext off-box, and arbitrary schemes / the SSRF surface are refused.
        if (!SiemWebhookUrl.IsAcceptable(url, out var reason))
        {
            _logger.LogWarning("Chat webhook URL rejected ({Reason}); message not posted. Configure an https webhook URL.", reason);
            return;
        }

        var payload = ChatPayload.Serialize(o.Format, message);
        var attempts = Math.Max(1, o.MaxAttempts);

        for (var attempt = 1; attempt <= attempts && !ct.IsCancellationRequested; attempt++)
        {
            try
            {
                using var client = _httpFactory.CreateClient("chat");
                client.Timeout = TimeSpan.FromSeconds(o.TimeoutSeconds > 0 ? o.TimeoutSeconds : 5);

                using var content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var resp = await client.PostAsync(url, content, ct).ConfigureAwait(false);
                if (resp.IsSuccessStatusCode) return;

                _logger.LogWarning("Chat webhook returned {Status} (attempt {Attempt}/{Max}).",
                    (int)resp.StatusCode, attempt, attempts);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Chat webhook POST failed (attempt {Attempt}/{Max}).", attempt, attempts);
            }

            if (attempt < attempts)
            {
                try { await Task.Delay(TimeSpan.FromMilliseconds(250 * attempt), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
            }
        }
    }
}
