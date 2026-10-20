using System.Net.Http.Headers;
using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Infrastructure.Siem;
using IncidentManager.Web.Secrets;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.Siem;

/// <summary>
/// Webhook transport for the security-event stream (F-18): POSTs each event as JSON to the configured
/// SIEM HTTP Collector, with a per-request timeout and a bounded retry. Best-effort — a failure is
/// logged and the event dropped (the audit chain remains the record of truth). Lives in Web because it
/// needs <see cref="IHttpClientFactory"/>. The auth token is resolved through <see cref="ISecretProvider"/>
/// (F-19), so <c>Siem:Webhook:Token</c> may be a literal or a <c>@cyberark:</c> reference. CAP-40: when the server's
/// configuration sets no token, the one saved in Administration (<see cref="StoredSecretStore"/>) is used, read per event so
/// a save applies without a restart. A token that's set but won't resolve or decrypt stops the send (fail closed): the
/// event isn't posted unauthenticated.
/// </summary>
public sealed class WebhookTransport : ISecurityEventTransport
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly IOptionsMonitor<SiemWebhookOptions> _options;
    private readonly ISecretProvider _secrets;
    private readonly ILogger<WebhookTransport> _logger;
    private readonly IDeliveryHealth? _health;   // CAP-04
    private readonly StoredSecretStore? _stored;   // CAP-40: the token saved in Administration, when the server sets none
    private int _tokenReported;                    // CAP-40: a token that won't resolve is logged once, until one does

    public WebhookTransport(IHttpClientFactory httpFactory, IOptionsMonitor<SiemWebhookOptions> options,
        ISecretProvider secrets, ILogger<WebhookTransport> logger, IDeliveryHealth? health = null, StoredSecretStore? stored = null)
    {
        _httpFactory = httpFactory;
        _options = options;
        _secrets = secrets;
        _logger = logger;
        _health = health;
        _stored = stored;
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
            if (!SiemWebhookUrl.IsAcceptable(o.Url, out var reason)) return $"not sending: the collector URL was refused ({reason})";
            // CAP-40: a saved token that won't decrypt here stops every event (a configured one that won't resolve shows as the
            // last error instead: the secret provider is asked per send, not here).
            return string.IsNullOrWhiteSpace(o.Token) && _stored?.Peek(StoredSecretKind.SiemWebhookToken).Unreadable == true
                ? "not sending: the webhook token saved in Administration can't be decrypted on this server; re-enter it"
                : null;
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

        // F-19: resolve the token (literal or @cyberark: reference) once per event; the provider caches. A reference string
        // is never sent as the bearer token. CAP-40: with none configured, the one saved in Administration. A token that's
        // set but won't resolve or decrypt stops the send: before, the event went without an auth header, which a collector
        // that wants one refuses (a 401 that pointed at the collector, not the secret) and one that doesn't should have had
        // no token set. As the SMTP sign-in (never a send without the sign-in that was asked for) and ADR 0018 §3.
        var (asked, token, where) = await TokenAsync(opts, ct).ConfigureAwait(false);
        if (asked && string.IsNullOrEmpty(token))
        {
            if (Interlocked.Exchange(ref _tokenReported, 1) == 0)
                _logger.LogWarning("The SIEM webhook token ({Where}) could not be {How}; events aren't sent until it is (first: event {EventId}).",
                    where, where == "server configuration" ? "resolved" : "decrypted", e.EventId);
            _health?.RecordFailure(DeliveryHealth.Siem(Name), where == "server configuration"
                ? "the token couldn't be resolved; not sent"
                : "the saved token can't be decrypted on this server; not sent");
            return where == "server configuration"
                ? "The webhook token (Siem:Webhook:Token) couldn't be resolved, so nothing was sent. See Diagnostics, Secret resolution."
                : "The webhook token saved in Administration can't be decrypted on this server (its Data Protection keys aren't " +
                  "here), so nothing was sent. Re-enter it under Integrations, SIEM webhook token.";
        }
        Interlocked.Exchange(ref _tokenReported, 0);

        var payload = SecurityEventJson.Serialize(e);
        var attempts = Math.Max(1, opts.MaxAttempts);
        string? lastError = null;
        string? shown = null;   // CAP-04: a status or a type for Diagnostics, never the collector's reply
        int? status = null;

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

    // CAP-40: whether a token is asked for (server configuration, else saved in Administration), the token (null when it won't
    // resolve or decrypt), and where it came from, for the log and the delivery card: never the value or the reference.
    private async Task<(bool Asked, string? Token, string Where)> TokenAsync(SiemWebhookOptions opts, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(opts.Token))
            return (true, await _secrets.ResolveAsync(opts.Token, ct).ConfigureAwait(false), "server configuration");
        if (_stored is null) return (false, null, "");
        // CAP-40 review: bounded, and a database that doesn't answer never throws here (which dropped the event and stalled
        // the lane for a connect timeout each): the token last read is used, or, when none was ever read, none (CantTell
        // isn't Saved), as before a token could be saved here.
        var saved = await _stored.ResolveAsync(StoredSecretKind.SiemWebhookToken, ct).ConfigureAwait(false);
        return (saved.Saved, saved.Value, "saved in Administration");
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
