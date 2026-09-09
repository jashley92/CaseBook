namespace IncidentManager.Infrastructure.Siem;

/// <summary>
/// Outbound SIEM webhook configuration (config section <c>Siem:Webhook</c>, F-18). Contains a secret
/// (<see cref="Token"/>) and an infrastructure endpoint, so it lives in server-side configuration only —
/// never the in-app editable settings catalog — and is shown read-only in Admin → Server configuration.
/// </summary>
public sealed class SiemWebhookOptions
{
    /// <summary>When false (default), the stream is off and <c>Emit</c> is a no-op (dev-safe).</summary>
    public bool Enabled { get; set; }

    /// <summary>HTTPS endpoint of the SIEM HTTP Log Collector (or any JSON webhook).</summary>
    public string Url { get; set; } = "";

    /// <summary>Bearer token / API key. Empty = no auth header sent.</summary>
    public string Token { get; set; } = "";

    /// <summary>Header carrying the token. Default "Authorization"; some collectors use "x-api-key".</summary>
    public string AuthHeader { get; set; } = "Authorization";

    /// <summary>Scheme prefix for the token on an Authorization header (e.g. "Bearer"). Blank = raw value.</summary>
    public string AuthScheme { get; set; } = "Bearer";

    /// <summary>Per-POST timeout.</summary>
    public int TimeoutSeconds { get; set; } = 5;

    /// <summary>Delivery attempts per event before it is dropped (>=1).</summary>
    public int MaxAttempts { get; set; } = 3;
}
