using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;
using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Secrets;

/// <summary>
/// Resolves <c>@cyberark:</c> secret references from the CyberArk Central Credential Provider (CCP /
/// AIMWebService REST) (F-19). Literal values pass straight through. A reference is fetched by
/// <c>AppID + Safe/Object</c> query over mutual TLS (CCP authenticates this app by client certificate
/// and/or allow-listed machine/OS-user — no CCP password is stored). Results are cached for a short TTL to
/// support rotation without hammering CCP; on a CCP error the configured <see cref="CyberArkOptions.FailClosed"/>
/// policy decides between resolving to null (safe degrade) and serving the last-known-good value.
/// </summary>
public sealed class CyberArkCcpSecretProvider : ISecretProvider, IDisposable
{
    private readonly HttpClient _http;
    private readonly CyberArkOptions _options;
    private readonly ILogger<CyberArkCcpSecretProvider> _logger;
    private readonly ISecretResolutionHealth _health;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _fetchLock = new(1, 1);

    private sealed record CacheEntry(string? Value, DateTimeOffset FetchedUtc);

    /// <summary>A CCP fetch failure carrying a caller-safe reason (status/code/config — never the secret).</summary>
    private sealed class SecretFetchException(string reason) : Exception(reason);

    private sealed class CcpResponse
    {
        [JsonPropertyName("Content")] public string? Content { get; set; }
        [JsonPropertyName("ErrorCode")] public string? ErrorCode { get; set; }
        [JsonPropertyName("ErrorMsg")] public string? ErrorMsg { get; set; }
    }

    public CyberArkCcpSecretProvider(IOptions<CyberArkOptions> options,
        ILogger<CyberArkCcpSecretProvider> logger, ISecretResolutionHealth health)
        : this(BuildHandler(options.Value, logger), options, logger, health) { }

    // Test seam: inject the transport handler so the CCP HTTP path is exercisable without a live CCP.
    internal CyberArkCcpSecretProvider(HttpMessageHandler handler, IOptions<CyberArkOptions> options,
        ILogger<CyberArkCcpSecretProvider> logger, ISecretResolutionHealth health)
    {
        _options = options.Value;
        _logger = logger;
        _health = health;
        _http = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds > 0 ? _options.TimeoutSeconds : 5)
        };
    }

    public async ValueTask<string?> ResolveAsync(string? configuredValue, CancellationToken ct = default)
    {
        // Literal → passthrough (the "fall back to config" choice is simply leaving a value literal).
        if (!SecretReference.TryParse(configuredValue, out var reference))
        {
            if (SecretReference.IsReference(configuredValue))
            {
                _logger.LogWarning("Malformed CyberArk secret reference; resolving as unavailable.");
                return null;
            }
            return configuredValue;
        }

        var key = reference.ToString();
        var ttl = TimeSpan.FromSeconds(Math.Max(1, _options.CacheTtlSeconds));

        if (_cache.TryGetValue(key, out var cached) && DateTimeOffset.UtcNow - cached.FetchedUtc < ttl)
            return cached.Value;

        await _fetchLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // Re-check: another caller may have refreshed while we waited.
            if (_cache.TryGetValue(key, out cached) && DateTimeOffset.UtcNow - cached.FetchedUtc < ttl)
                return cached.Value;

            string value;
            try
            {
                value = await FetchAsync(reference, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Never surface a fetch failure to the caller — a secret it can't get is "unavailable".
                // A SecretFetchException already carries a caller-safe reason; anything else is unexpected
                // (log the full exception in that case only).
                var expected = ex is SecretFetchException;
                var reason = expected ? ex.Message : ex.GetType().Name;
                _logger.LogWarning(expected ? null : ex, "CyberArk CCP fetch failed for {Reference}: {Reason}",
                    key, reason);
                _health.RecordFailure(key, reason);
                return OnFetchFailed(key, cached);              // apply fail policy; don't cache the failure
            }

            _cache[key] = new CacheEntry(value, DateTimeOffset.UtcNow);
            _health.RecordSuccess(key);
            return value;
        }
        finally
        {
            _fetchLock.Release();
        }
    }

    /// <summary>Fail policy for a failed fetch: last-known-good when not fail-closed, else null.</summary>
    private string? OnFetchFailed(string key, CacheEntry? cached)
    {
        if (!_options.FailClosed && cached is not null)
        {
            _logger.LogWarning("Serving last-known-good secret for {Reference} (FailClosed=false).", key);
            return cached.Value;                               // degrade to stale-but-real, not to plaintext config
        }
        return null;                                           // fail closed
    }

    /// <summary>Fetches the secret, or throws <see cref="SecretFetchException"/> with a caller-safe reason.</summary>
    private async Task<string> FetchAsync(SecretReference reference, CancellationToken ct)
    {
        if (!Uri.TryCreate(_options.BaseUrl, UriKind.Absolute, out var baseUri)
            || !baseUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            throw new SecretFetchException("Secrets:CyberArk:BaseUrl is not an absolute https URL");
        if (string.IsNullOrWhiteSpace(_options.AppId))
            throw new SecretFetchException("Secrets:CyberArk:AppId is not configured");

        var query = new List<string> { "AppID=" + Uri.EscapeDataString(_options.AppId) };
        query.AddRange(reference.Query.Select(p =>
            $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        var url = $"{_options.BaseUrl.TrimEnd('/')}/api/Accounts?{string.Join('&', query)}";

        using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
        // CCP returns the error detail in the body as JSON; parse it either way (never read/log Content on error).
        var body = await resp.Content.ReadFromJsonAsync<CcpResponse>(ct).ConfigureAwait(false);

        if (!resp.IsSuccessStatusCode)
            throw new SecretFetchException($"CCP returned HTTP {(int)resp.StatusCode} ({body?.ErrorCode})".Trim());
        if (string.IsNullOrEmpty(body?.Content))
            throw new SecretFetchException("CCP returned success with no secret content");
        return body.Content;
    }

    private static HttpClientHandler BuildHandler(CyberArkOptions options, ILogger logger)
    {
        var handler = new HttpClientHandler { AutomaticDecompression = DecompressionMethods.All };
        var cert = LoadClientCertificate(options, logger);
        if (cert is not null) handler.ClientCertificates.Add(cert);
        return handler;
    }

    private static X509Certificate2? LoadClientCertificate(CyberArkOptions options, ILogger logger)
    {
        var thumb = options.ClientCertificateThumbprint?.Replace(" ", "").Trim();
        if (string.IsNullOrEmpty(thumb)) return null;         // CCP authenticates by machine / OS-user
        if (!OperatingSystem.IsWindows())
        {
            logger.LogWarning("A CyberArk client-certificate thumbprint is configured but the machine "
                + "certificate store is only available on Windows; proceeding without a client certificate.");
            return null;
        }

        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            var match = store.Certificates.Find(X509FindType.FindByThumbprint, thumb, validOnly: false);
            if (match.Count == 0)
            {
                logger.LogError("CyberArk client certificate with thumbprint {Thumb} not found in "
                    + "LocalMachine\\My; proceeding without a client certificate.", thumb);
                return null;
            }
            return match[0];
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to load the CyberArk client certificate; proceeding without one.");
            return null;
        }
    }

    public void Dispose()
    {
        _http.Dispose();
        _fetchLock.Dispose();
    }
}
