namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Resolves a *configured* secret value into its actual secret (F-19). A call site reads its secret from
/// configuration as it always has, then passes the raw value through this seam before use:
/// <code>var token = await _secrets.ResolveAsync(opts.Token, ct);</code>
///
/// <para>Two behaviours, selected per value so adoption stays opt-in:</para>
/// <list type="bullet">
///   <item><description><b>Literal (default):</b> a plain value is returned unchanged — the existing
///     "secret in config/env" path. Leaving a value literal is the "fall back to config" choice.</description></item>
///   <item><description><b>Reference:</b> a value of the form <c>@cyberark:Safe=&lt;safe&gt;;Object=&lt;object&gt;</c>
///     is fetched from an external secret store (CyberArk CCP) at runtime, so no secret is stored in config
///     at all. Failure to resolve a reference returns <c>null</c> (fail-closed) rather than the reference
///     text — a caller must treat null as "secret unavailable", never as the secret.</description></item>
/// </list>
///
/// The default registration is a passthrough that resolves literals and fails a reference closed; enabling
/// <c>Secrets:CyberArk</c> swaps in the provider that can satisfy references. Callers never learn which.
/// </summary>
public interface ISecretProvider
{
    /// <summary>
    /// Resolves <paramref name="configuredValue"/> to a secret. Returns null/empty unchanged, a literal
    /// unchanged, and a reference's fetched value (or <c>null</c> if it cannot be resolved). Implementations
    /// must not throw for an unresolvable reference — they return null so the dependent feature degrades
    /// safely instead of taking down the caller.
    /// </summary>
    ValueTask<string?> ResolveAsync(string? configuredValue, CancellationToken ct = default);
}
