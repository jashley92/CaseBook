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

    public WebhookTransport(IHttpClientFactory httpFactory, IOptionsMonitor<SiemWebhookOptions> options,
        ISecretProvider secrets, ILogger<WebhookTransport> logger)
    {
        _httpFactory = httpFactory;
        _options = options;
        _secrets = secrets;
        _logger = logger;
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

    public async Task SendAsync(SecurityEvent e, CancellationToken ct)
    {
        var opts = _options.CurrentValue;
        if (!opts.Enabled || string.IsNullOrWhiteSpace(opts.Url)) return;

        // S-06: refuse to send the token/event stream to a non-https (or non-loopback-http) endpoint.
        if (!SiemWebhookUrl.IsAcceptable(opts.Url, out var reason))
        {
            _logger.LogWarning(
                "SIEM webhook URL rejected ({Reason}); event {EventId} not sent. Configure an https collector URL.",
                reason, e.EventId);
            return;
        }

        var payload = SecurityEventJson.Serialize(e);
        var attempts = Math.Max(1, opts.MaxAttempts);

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
                if (resp.IsSuccessStatusCode) return;

                _logger.LogWarning("SIEM webhook returned {Status} for event {EventId} (attempt {Attempt}/{Max}).",
                    (int)resp.StatusCode, e.EventId, attempt, attempts);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "SIEM webhook POST failed for event {EventId} (attempt {Attempt}/{Max}).",
                    e.EventId, attempt, attempts);
            }

            if (attempt < attempts)
            {
                try { await Task.Delay(TimeSpan.FromMilliseconds(250 * attempt), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
            }
        }
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
