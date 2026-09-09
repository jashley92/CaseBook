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

    Task SendAsync(SecurityEvent e, CancellationToken ct);
}
