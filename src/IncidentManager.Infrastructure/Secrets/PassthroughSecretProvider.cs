using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Logging;

namespace IncidentManager.Infrastructure.Secrets;

/// <summary>
/// Default <see cref="ISecretProvider"/> (F-19): resolves literal values from config/env and has no
/// external secret store. A literal is returned unchanged; a <c>@cyberark:</c> reference cannot be
/// satisfied here, so it fails <b>closed</b> — logged once and resolved to <c>null</c> — never returning
/// the reference text as if it were the secret. Enable <c>Secrets:CyberArk</c> to swap in a provider that
/// can fetch references.
/// </summary>
public sealed class PassthroughSecretProvider(ILogger<PassthroughSecretProvider> logger) : ISecretProvider
{
    public ValueTask<string?> ResolveAsync(string? configuredValue, CancellationToken ct = default)
    {
        if (SecretReference.IsReference(configuredValue))
        {
            logger.LogWarning(
                "A secret is configured as a CyberArk reference but no secret provider is enabled " +
                "(Secrets:CyberArk:Enabled=false); resolving it as unavailable. Enable the CyberArk " +
                "provider or set a literal value.");
            return ValueTask.FromResult<string?>(null);
        }

        return ValueTask.FromResult(configuredValue);
    }
}
