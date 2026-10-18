using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Siem;
using IncidentManager.Web.Secrets;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.Notifications;

/// <summary>
/// Posts case-lifecycle notifications to a Slack/Teams incoming webhook (PROD-02): a broadcast to a shared
/// SOC channel alongside the per-recipient email path. Mirrors the SIEM <c>WebhookTransport</c> — best-effort,
/// time-bounded, bounded retry, https-only egress (the webhook URL carries the channel secret) — and lives in
/// Web because it needs <see cref="IHttpClientFactory"/>. The URL is resolved through <see cref="ISecretProvider"/>
/// so it may be a literal or a <c>@cyberark:</c> reference (F-19). Never throws into the caller.
/// CAP-40: when the server's configuration sets no URL, the one saved in Administration (<see cref="StoredSecretStore"/>)
/// is used, read per post so a save applies without a restart; one that won't decrypt here isn't posted to (fail closed).
/// </summary>
public sealed class ChatWebhookNotifier : IChatNotifier
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly IOptionsMonitor<ChatOptions> _options;
    private readonly ISecretProvider _secrets;
    private readonly ILogger<ChatWebhookNotifier> _logger;
    private readonly OutboundCircuit _circuit;
    private readonly IDeliveryHealth? _health;   // CAP-04: what Diagnostics shows of the webhook
    private readonly StoredSecretStore? _stored;   // CAP-40: the URL saved in Administration, when the server sets none

    public ChatWebhookNotifier(IHttpClientFactory httpFactory, IOptionsMonitor<ChatOptions> options,
        ISecretProvider secrets, ILogger<ChatWebhookNotifier> logger, OutboundCircuit? circuit = null, IDeliveryHealth? health = null,
        StoredSecretStore? stored = null)
    {
        _httpFactory = httpFactory;
        _options = options;
        _secrets = secrets;
        _logger = logger;
        _circuit = circuit ?? new OutboundCircuit();
        _health = health;
        _stored = stored;
    }

    // CAP-40: a URL in the server's configuration, or one saved in Administration (even one that won't decrypt here: its
    // post then fails, so a scheduled broadcast is tried again once it's re-entered, rather than marked sent). CAP-40 review:
    // and while the database can't tell (down since startup, nothing read): its post fails too, for the same reason.
    public bool Enabled
    {
        get
        {
            var o = _options.CurrentValue;
            if (!o.Enabled) return false;
            if (!string.IsNullOrWhiteSpace(o.WebhookUrl)) return true;
            return _stored?.Peek(StoredSecretKind.ChatWebhookUrl) is { } saved && (saved.Set || saved.Unread);
        }
    }

    // CAP-40: on, but nothing will post: shown as stopped on the delivery card, with why.
    public string? StoppedReason
    {
        get
        {
            var o = _options.CurrentValue;
            if (!o.Enabled || !string.IsNullOrWhiteSpace(o.WebhookUrl)) return null;
            var saved = _stored?.Peek(StoredSecretKind.ChatWebhookUrl);
            if (saved is { Unread: true })
                return "not posting: the webhook URL saved in Administration can't be read (the database isn't answering); " +
                       "posts are tried again once it does";
            if (saved is not { Set: true }) return "not posting: no webhook URL is set (Chat:Webhook:WebhookUrl, or Settings, Notifications)";
            return saved.Unreadable
                ? "not posting: the webhook URL saved in Administration can't be decrypted on this server; re-enter it"
                : null;
        }
    }

    // WF-20: a post that didn't go is a delivery failure, as an email's is, so a scan's broadcast is tried again.
    public async Task SendAsync(ChatNotification message, CancellationToken ct = default)
    {
        if (await PostAsync(message, test: false, ct).ConfigureAwait(false) is not null) DeliveryWatch.ReportFailure();
    }

    // BUG-576: the admin's test always posts (and a good one ends a back-off).
    public Task<string?> SendTestAsync(ChatNotification message, CancellationToken ct = default) => PostAsync(message, test: true, ct);

    // Returns null when the message posted (or chat is off), else a short reason for the admin test button.
    private async Task<string?> PostAsync(ChatNotification message, bool test, CancellationToken ct)
    {
        var o = _options.CurrentValue;
        if (!o.Enabled) return null;

        string? url;
        if (!string.IsNullOrWhiteSpace(o.WebhookUrl))
        {
            // The webhook URL is itself the channel credential; resolve it (literal or @cyberark: reference).
            url = await _secrets.ResolveAsync(o.WebhookUrl, ct).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(url))
            {
                _logger.LogWarning("Chat webhook URL could not be resolved; message not posted.");
                _health?.RecordFailure(DeliveryHealth.Chat, "the webhook URL couldn't be resolved");   // CAP-04
                return "The webhook URL couldn't be resolved.";
            }
        }
        else
        {
            // CAP-40: the URL saved in Administration, read now. None saved: chat is off, as with no URL configured.
            var saved = _stored is null ? StoredSecretValue.NotSaved
                : await _stored.ResolveAsync(StoredSecretKind.ChatWebhookUrl, ct).ConfigureAwait(false);
            if (saved.Unread)
            {
                // CAP-40 review: the database can't tell whether one is saved (bounded; what was last read answers when there
                // is any). Not "chat is off": the failure counts, so a scheduled broadcast is tried again, not marked sent.
                _health?.RecordFailure(DeliveryHealth.Chat, "the saved webhook URL couldn't be read (database not answering)");
                return "The webhook URL saved in Administration couldn't be read: the database isn't answering. Try again shortly.";
            }
            if (!saved.Saved) return null;
            if (saved.Unreadable)
            {
                // Fail closed. The store logged it once; the failure counts, so a scheduled broadcast is tried again.
                _health?.RecordFailure(DeliveryHealth.Chat, "the saved webhook URL can't be decrypted on this server");
                return "The webhook URL saved in Administration can't be decrypted on this server (its Data Protection keys " +
                       "aren't here). Re-enter it under Settings, Notifications, Team chat webhook.";
            }
            url = saved.Value!;
        }

        // Same egress guard as the SIEM webhook (S-06): https required (http only to loopback) so the secret
        // URL is never sent in cleartext off-box, and arbitrary schemes / the SSRF surface are refused.
        if (!SiemWebhookUrl.IsAcceptable(url, out var reason))
        {
            _logger.LogWarning("Chat webhook URL rejected ({Reason}); message not posted. Configure an https webhook URL.", reason);
            return $"The webhook URL was refused ({reason}). Use an https URL.";
        }

        // BUG-576: a webhook that just stalled or failed isn't waited on (timeout times attempts) by every assign,
        // reclassify, mention and handoff. The target is the resolved URL (kept in memory only, never logged).
        var target = "chat:" + url;
        var payload = ChatPayload.Serialize(o.Format, message);   // BUG-607: before taking a probe's turn
        if (!test && !_circuit.TryEnter(target))
        {
            _logger.LogWarning("The chat webhook isn't answering; message not posted until it's tried again.");
            return "The webhook isn't answering; posts are paused for a few minutes.";
        }

        var attempts = Math.Max(1, o.MaxAttempts);
        string? lastError = null;
        var unreachable = false;   // the last attempt timed out, couldn't connect, or got a server error
        string? shown = null;      // CAP-04: the last failure for Diagnostics: a status or a type, never the URL
        int? status = null;

        for (var attempt = 1; attempt <= attempts && !ct.IsCancellationRequested; attempt++)
        {
            try
            {
                using var client = _httpFactory.CreateClient("chat");
                client.Timeout = TimeSpan.FromSeconds(o.TimeoutSeconds > 0 ? o.TimeoutSeconds : 5);

                using var content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var resp = await client.PostAsync(url, content, ct).ConfigureAwait(false);
                if (resp.IsSuccessStatusCode)
                {
                    _circuit.Succeeded(target);
                    _health?.RecordSuccess(DeliveryHealth.Chat);
                    return null;
                }
                lastError = $"The webhook answered {(int)resp.StatusCode} {resp.ReasonPhrase}.";
                (shown, status) = ($"HTTP {(int)resp.StatusCode}", (int)resp.StatusCode);
                unreachable = (int)resp.StatusCode >= 500 || resp.StatusCode == System.Net.HttpStatusCode.TooManyRequests;

                _logger.LogWarning("Chat webhook returned {Status} (attempt {Attempt}/{Max}).",
                    (int)resp.StatusCode, attempt, attempts);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return Canceled();
            }
            catch (Exception ex)
            {
                lastError = ex is TaskCanceledException ? "The webhook didn't answer in time." : ex.GetBaseException().Message;
                (shown, status) = (ex is TaskCanceledException ? "timed out" : ex.GetBaseException().GetType().Name, null);
                unreachable = true;
                _logger.LogWarning(ex, "Chat webhook POST failed (attempt {Attempt}/{Max}).", attempt, attempts);
            }

            if (attempt < attempts)
            {
                try { await Task.Delay(TimeSpan.FromMilliseconds(250 * attempt), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return Canceled(); }
            }
        }
        // BUG-576: backed off only when it didn't answer; one that answered with a refusal (a 4xx) isn't hung.
        if (unreachable) _circuit.Failed(target);
        else if (lastError is not null) _circuit.Succeeded(target);
        else return Canceled();   // cancelled before the first attempt: not posted
        _health?.RecordFailure(DeliveryHealth.Chat, shown ?? "failed", status);
        if (_circuit.RetryIn(target) is var wait && wait > TimeSpan.Zero)
            _health?.RecordBackOff(DeliveryHealth.Chat, _circuit.Time.GetUtcNow() + wait);
        return lastError;

        // BUG-607: a cancelled post says nothing about the webhook; the probe's turn it may hold is handed back (held,
        // every post failed fast for ten minutes).
        string Canceled()
        {
            if (!test) _circuit.Release(target);
            return "Canceled.";
        }
    }
}
