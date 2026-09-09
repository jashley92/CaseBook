namespace IncidentManager.Application.Security;

/// <summary>
/// The outbound security-event stream (F-18). <see cref="Emit"/> is <b>synchronous and non-blocking</b> —
/// it hands the event to a bounded in-memory queue and returns immediately, so a slow or unreachable
/// SIEM endpoint can never add latency to, or fail, the user action that produced the event. A
/// background dispatcher delivers queued events best-effort. When the stream is disabled or
/// unconfigured, <see cref="Emit"/> is a no-op.
/// </summary>
public interface ISecurityEventSink
{
    /// <summary>Enqueue an event for delivery. Never throws; never blocks on the network.</summary>
    void Emit(SecurityEvent e);
}
