using IncidentManager.Application.Security;

namespace IncidentManager.Infrastructure.Siem;

/// <summary>
/// One delivery transport for the security-event stream (F-18) — webhook, syslog, event log, … The
/// queue enqueues an event once; the dispatcher fans it out to every <see cref="Enabled"/> transport.
/// Implementations should be best-effort and time-bounded; the dispatcher also guards each call so one
/// transport failing never stops the others.
/// </summary>
public interface ISecurityEventTransport
{
    /// <summary>Short id for logs (e.g. "webhook", "syslog").</summary>
    string Name { get; }

    /// <summary>Whether this transport is currently configured to deliver (read live from options).</summary>
    bool Enabled { get; }

    /// <summary>
    /// CAP-04 review: whether this transport is switched on in its options, whether or not it can deliver right now.
    /// The Diagnostics delivery card picks its rows by this, so a transport that's on but has stopped (an Event Log
    /// source that's missing, a collector with no address) shows as failing instead of vanishing. Read live from options.
    /// </summary>
    bool Configured => Enabled;

    /// <summary>
    /// CAP-04 review: why a <see cref="Configured"/> transport isn't delivering (e.g. "stopped until restart: event source
    /// missing"), or null when it is delivering or isn't on. A short reason for an administrator, never a secret.
    /// </summary>
    string? StoppedReason => null;

    Task SendAsync(SecurityEvent e, CancellationToken ct);

    /// <summary>
    /// For the Diagnostics test button only: sends like <see cref="SendAsync"/> but returns why delivery failed
    /// (null when it went out). Transports that can't observe delivery keep this default.
    /// </summary>
    async Task<string?> SendTestAsync(SecurityEvent e, CancellationToken ct)
    {
        await SendAsync(e, ct);
        return null;
    }
}
