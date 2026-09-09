using System.Threading.Channels;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using Microsoft.Extensions.Logging;

namespace IncidentManager.Infrastructure.Siem;

/// <summary>
/// The security-event sink (F-18): <see cref="Emit"/> stamps the event and drops it into a bounded
/// channel, returning immediately — no user action ever blocks on delivery. The
/// <c>SecurityEventDispatcher</c> drains <see cref="Reader"/> and fans each event out to the enabled
/// transports (webhook, syslog, …). <see cref="Emit"/> is a no-op when <b>no</b> transport is enabled,
/// so a fully-disabled stream queues nothing.
/// </summary>
public sealed class SecurityEventQueue : ISecurityEventSink
{
    private readonly Channel<SecurityEvent> _channel;
    private readonly IReadOnlyList<ISecurityEventTransport> _transports;
    private readonly IClock _clock;
    private readonly ILogger<SecurityEventQueue> _logger;
    private readonly string _host = Environment.MachineName;

    private long _dropped;

    public SecurityEventQueue(IEnumerable<ISecurityEventTransport> transports, IClock clock,
        ILogger<SecurityEventQueue> logger, int capacity = 2048)
    {
        _transports = transports.ToList();
        _clock = clock;
        _logger = logger;

        var cap = Math.Max(16, capacity);
        // Bounded + FullMode.Wait so a full queue makes TryWrite return false (never blocks the caller) —
        // we drop-and-count rather than back-pressure the request thread.
        _channel = Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(cap)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });
    }

    /// <summary>Read side for the background dispatcher.</summary>
    public ChannelReader<SecurityEvent> Reader => _channel.Reader;

    private bool AnyTransportEnabled()
    {
        foreach (var t in _transports)
            if (t.Enabled) return true;
        return false;
    }

    public void Emit(SecurityEvent e)
    {
        try
        {
            if (!AnyTransportEnabled()) return;

            var stamped = e with { AtUtc = _clock.UtcNow, Host = _host };
            if (!_channel.Writer.TryWrite(stamped))
            {
                var n = Interlocked.Increment(ref _dropped);
                if (n == 1 || n % 100 == 0)
                    _logger.LogWarning("SIEM stream queue full — dropped {Dropped} event(s); last id {EventId}.", n, e.EventId);
            }
        }
        catch (Exception ex)
        {
            // Contract: Emit never throws into the caller's path.
            _logger.LogWarning(ex, "SIEM stream: failed to enqueue event {EventId}.", e.EventId);
        }
    }
}
