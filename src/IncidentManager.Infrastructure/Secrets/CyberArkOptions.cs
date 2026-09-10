namespace IncidentManager.Infrastructure.Secrets;

/// <summary>
/// CyberArk Central Credential Provider (CCP / AIMWebService) settings (config section
/// <c>Secrets:CyberArk</c>, F-19). Server-side configuration only — it holds an endpoint and an AppID, not
/// a credential: CCP itself authenticates this application by <b>client certificate</b> and/or the
/// allow-listed <b>machine / OS user</b> configured on the CCP side (that is the point of CCP — there is no
/// CCP password to store). Disabled by default; when off, the passthrough provider is used instead.
/// </summary>
public sealed class CyberArkOptions
{
    /// <summary>When true, <c>@cyberark:</c> references are fetched from CCP. Default false (passthrough).</summary>
    public bool Enabled { get; set; }

    /// <summary>Base URL of the AIMWebService, e.g. <c>https://ccp.corp.example/AIMWebService</c>. Must be HTTPS.</summary>
    public string BaseUrl { get; set; } = "";

    /// <summary>The CCP Application ID this app is provisioned as (query param <c>AppID</c>).</summary>
    public string AppId { get; set; } = "";

    /// <summary>
    /// Optional thumbprint (hex, no spaces) of a client certificate in <c>LocalMachine\My</c> to present for
    /// mutual TLS. Omit if CCP authenticates this app solely by machine / OS-user allow-listing.
    /// </summary>
    public string ClientCertificateThumbprint { get; set; } = "";

    /// <summary>How long a fetched secret is cached before re-fetch. Supports rotation without a restart.</summary>
    public int CacheTtlSeconds { get; set; } = 300;

    /// <summary>Per-request timeout for the CCP call.</summary>
    public int TimeoutSeconds { get; set; } = 5;

    /// <summary>
    /// On a CCP error: when true (default) resolve to <c>null</c> so the dependent feature degrades safely;
    /// when false, serve the <b>last-known-good</b> cached value past its TTL (never a plaintext-config
    /// fallback) so a transient CCP outage doesn't drop a working secret.
    /// </summary>
    public bool FailClosed { get; set; } = true;
}
