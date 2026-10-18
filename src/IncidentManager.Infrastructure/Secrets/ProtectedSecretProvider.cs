using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Logging;

namespace IncidentManager.Infrastructure.Secrets;

/// <summary>
/// CAP-05 (ADR 0018): the <see cref="ISecretProvider"/> every caller gets. It opens <c>@protected:</c> values itself, with
/// the certificate in the store, and hands every other value to the provider behind it (passthrough, or CyberArk when
/// <c>Secrets:CyberArk</c> is on), so a protected secret works with or without CyberArk and no caller changes. Fail
/// closed, as a CyberArk reference is: a value that won't open resolves to null, logged once (by its certificate's
/// thumbprint, never its content) until it opens. An opened value is kept in memory, as CyberArk's cache keeps a
/// fetched one, so the private key isn't used on every send.
/// </summary>
public sealed class ProtectedSecretProvider : ISecretProvider
{
    private readonly ISecretProvider _inner;
    private readonly ILogger<ProtectedSecretProvider> _logger;
    private readonly Func<string, X509Certificate2> _findCertificate;
    private readonly ConcurrentDictionary<string, string> _opened = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _reported = new(StringComparer.Ordinal);

    public ProtectedSecretProvider(ISecretProvider inner, ILogger<ProtectedSecretProvider> logger,
        Func<string, X509Certificate2>? findCertificate = null)
    {
        _inner = inner;
        _logger = logger;
        _findCertificate = findCertificate ?? ProtectedSecret.FindInStore;   // test seam: certificates made in memory
    }

    public ValueTask<string?> ResolveAsync(string? configuredValue, CancellationToken ct = default)
    {
        if (!ProtectedSecret.IsProtected(configuredValue)) return _inner.ResolveAsync(configuredValue, ct);

        var value = configuredValue.Trim();
        if (_opened.TryGetValue(value, out var cached)) return ValueTask.FromResult<string?>(cached);
        if (ProtectedSecret.TryOpen(value, _findCertificate, out var secret, out var reason))
        {
            _opened[value] = secret;
            _reported.TryRemove(value, out _);
            return ValueTask.FromResult<string?>(secret);
        }
        if (_reported.TryAdd(value, 0))
            _logger.LogWarning("A @protected: secret (certificate {Thumbprint}) couldn't be opened, so it's unavailable: {Reason}. " +
                               "Grant the app-pool account read on the certificate's private key, or make the value again with " +
                               "casebook-keytool protect-secret.", ProtectedSecret.ThumbprintOf(value) ?? "unknown", reason);
        return ValueTask.FromResult<string?>(null);
    }
}
