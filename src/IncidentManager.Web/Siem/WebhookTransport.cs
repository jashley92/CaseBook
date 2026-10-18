using System.Net.Http.Headers;
using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Infrastructure.Siem;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.Siem;

/// <summary>
/// Webhook transport for the security-event stream (F-18): POSTs each event as JSON to the configured
/// SIEM HTTP Collector, with a per-request timeout and a bounded retry. Best-effort — a failure is
/// logged and the event dropped (the audit chain remains the record of truth). Lives in Web because it
/// needs <see cref="IHttpClientFactory"/>. The auth token is resolved through <see cref="ISecretProvider"/>
/// (F-19), so <c>Siem:Webhook:Token</c> may be a literal or a <c>@cyberark:</c> reference.
/// </summary>
public sealed class WebhookTransport : ISecurityEventTransport
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly IOptionsMonitor<SiemWebhookOptions> _options;
    private readonly ISecretProvider _secrets;
    private readonly ILogger<WebhookTransport> _logger;
    private readonly IDeliveryHealth? _health;   // CAP-04

    public WebhookTransport(IHttpClientFactory httpFactory, IOptionsMonitor<SiemWebhookOptions> options,
        ISecretProvider secrets, ILogger<WebhookTransport> logger, IDeliveryHealth? health = null)
    {
        _httpFactory = httpFactory;
        _options = options;
        _secrets = secrets;
        _logger = logger;
        _health = health;
    }

    public string Name => "webhook";

    public bool Enabled
    {
        get
        {
            var o = _options.CurrentValue;
            return o.Enabled && !string.IsNullOrWhiteSpace(o.Url);
        }
    }

    // CAP-04 review: on in its options but with no URL, or one S-06 refuses, nothing goes; the delivery card says why.
    public bool Configured => _options.CurrentValue.Enabled;

    public string? StoppedReason
    {
        get
        {
            var o = _options.CurrentValue;
            if (!o.Enabled) return null;
            if (string.IsNullOrWhiteSpace(o.Url)) return "not sending: no collector URL is set (Siem:Webhook:Url)";
            return SiemWebhookUrl.IsAcceptable(o.Url, out var reason) ? null : $"not sending: the collector URL was refused ({reason})";
        }
    }

    public Task SendAsync(SecurityEvent e, CancellationToken ct) => PostAsync(e, ct);

    public Task<string?> SendTestAsync(SecurityEvent e, CancellationToken ct) => PostAsync(e, ct);

    // Returns null when the event posted (or the transport is off), else a short reason for the test button.
    private async Task<string?> PostAsync(SecurityEvent e, CancellationToken ct)
    {
        var opts = _options.CurrentValue;
        if (!opts.Enabled || string.IsNullOrWhiteSpace(opts.Url)) return null;

        // S-06: refuse to send the token/event stream to a non-https (or non-loopback-http) endpoint.
        if (!SiemWebhookUrl.IsAcceptable(opts.Url, out var reason))
        {
            _logger.LogWarning(
                "SIEM webhook URL rejected ({Reason}); event {EventId} not sent. Configure an https collector URL.",
                reason, e.EventId);
            _health?.RecordFailure(DeliveryHealth.Siem(Name), "the collector URL was refused");   // CAP-04
            return $"The collector URL was refused ({reason}). Use an https URL.";
        }

        var payload = SecurityEventJson.Serialize(e);
        var attempts = Math.Max(1, opts.MaxAttempts);
        string? lastError = null;
        string? shown = null;   // CAP-04: a status or a type for Diagnostics, never the collector's reply
        int? status = null;

        // F-19: resolve the token (literal or @cyberark: reference) once per event; the provider caches.
        // A configured-but-unresolvable secret comes back null → we send no auth header (fail-closed) rather
        // than leaking a reference string as a bearer token.
        var token = await _secrets.ResolveAsync(opts.Token, ct).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(opts.Token) && string.IsNullOrEmpty(token))
            _logger.LogWarning("SIEM webhook token could not be resolved; sending event {EventId} without auth.",
                e.EventId);

        for (var attempt = 1; attempt <= attempts && !ct.IsCancellationRequested; attempt++)
        {
            try
            {
                using var client = _httpFactory.CreateClient("siem");
                client.Timeout = TimeSpan.FromSeconds(opts.TimeoutSeconds > 0 ? opts.TimeoutSeconds : 5);

                using var req = new HttpRequestMessage(HttpMethod.Post, opts.Url)
                {
                    Content = new StringContent(payload, Encoding.UTF8, "application/json")
                };
                ApplyAuth(req, opts, token);

                using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
                if (resp.IsSuccessStatusCode)
                {
                    _health?.RecordSuccess(DeliveryHealth.Siem(Name));
                    return null;
                }
                lastError = $"The collector answered {(int)resp.StatusCode} {resp.ReasonPhrase}.";
                (shown, status) = ($"HTTP {(int)resp.StatusCode}", (int)resp.StatusCode);

                _logger.LogWarning("SIEM webhook returned {Status} for event {EventId} (attempt {Attempt}/{Max}).",
                    (int)resp.StatusCode, e.EventId, attempt, attempts);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return "Canceled.";
            }
            catch (Exception ex)
            {
                lastError = ex is TaskCanceledException ? "The collector didn't answer in time." : ex.GetBaseException().Message;
                (shown, status) = (ex is TaskCanceledException ? "timed out" : ex.GetBaseException().GetType().Name, null);
                _logger.LogWarning(ex, "SIEM webhook POST failed for event {EventId} (attempt {Attempt}/{Max}).",
                    e.EventId, attempt, attempts);
            }

            if (attempt < attempts)
            {
                try { await Task.Delay(TimeSpan.FromMilliseconds(250 * attempt), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return "Canceled."; }
            }
        }
        if (lastError is not null) _health?.RecordFailure(DeliveryHealth.Siem(Name), shown ?? "failed", status);
        return lastError;
    }

    private static void ApplyAuth(HttpRequestMessage req, SiemWebhookOptions opts, string? token)
    {
        if (string.IsNullOrWhiteSpace(token)) return;

        if (string.Equals(opts.AuthHeader, "Authorization", StringComparison.OrdinalIgnoreCase))
            req.Headers.Authorization = string.IsNullOrWhiteSpace(opts.AuthScheme)
                ? new AuthenticationHeaderValue(token)
                : new AuthenticationHeaderValue(opts.AuthScheme, token);
        else
            req.Headers.TryAddWithoutValidation(opts.AuthHeader, token);
    }
}
