using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Infrastructure.Siem;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Drains the <see cref="SecurityEventQueue"/> and fans each security event out to every enabled
/// transport (webhook, syslog, …) (F-18). Delivery is best-effort: each transport call is guarded so one
/// failing transport never stops the others, and nothing here throws out of the loop. The audit chain
/// remains the system of record, so a dropped event is not a data-integrity concern.
/// <para>
/// BUG-290: each transport has its own queue and worker. Sent to in turn, a black-holed webhook (three tries of five
/// seconds each per event) held every event behind it, the Event Log's included, until the shared queue filled and new
/// events, integrity alarms among them, were dropped. A slow transport now only backs up its own queue, which drops its
/// oldest routine events when full; critical events have a lane of their own and are sent first.
/// </para>
/// </summary>
public sealed class SecurityEventDispatcher : BackgroundService
{
    internal const int RoutineCapacity = 1024;
    internal const int CriticalCapacity = 256;

    private readonly SecurityEventQueue _queue;
    private readonly IReadOnlyList<ISecurityEventTransport> _transports;
    private readonly ILogger<SecurityEventDispatcher> _logger;
    private readonly IDeliveryHealth? _health;   // CAP-04: each transport's queue depth and drops, for Diagnostics

    public SecurityEventDispatcher(SecurityEventQueue queue, IEnumerable<ISecurityEventTransport> transports,
        ILogger<SecurityEventDispatcher> logger, IDeliveryHealth? health = null)
    {
        _queue = queue;
        _transports = transports.ToList();
        _logger = logger;
        _health = health;
    }

    /// <summary>One transport's queue: critical events ahead of routine ones, each lane bounded, oldest dropped first.</summary>
    internal sealed class Lane(ISecurityEventTransport transport) : IDisposable
    {
        private readonly object _gate = new();
        private readonly Queue<SecurityEvent> _critical = new();
        private readonly Queue<SecurityEvent> _routine = new();
        private readonly SemaphoreSlim _available = new(0);   // one count per queued event

        public ISecurityEventTransport Transport { get; } = transport;
        public long Dropped { get; private set; }

        /// <summary>CAP-04: events waiting, both lanes.</summary>
        public int Depth
        {
            get { lock (_gate) return _critical.Count + _routine.Count; }
        }

        public void Add(SecurityEvent e)
        {
            var critical = e.Severity == SecuritySeverity.Critical;
            lock (_gate)
            {
                var q = critical ? _critical : _routine;
                if (q.Count >= (critical ? CriticalCapacity : RoutineCapacity))
                {
                    q.Dequeue();   // full: the oldest of its kind goes, and the count of queued events stays the same
                    Dropped++;
                    q.Enqueue(e);
                    return;
                }
                q.Enqueue(e);
            }
            _available.Release();
        }

        public async Task<SecurityEvent> TakeAsync(CancellationToken ct)
        {
            await _available.WaitAsync(ct).ConfigureAwait(false);
            lock (_gate) return _critical.Count > 0 ? _critical.Dequeue() : _routine.Dequeue();
        }

        public void Dispose() => _available.Dispose();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var lanes = _transports.Select(t => new Lane(t)).ToList();
        var workers = lanes.Select(l => Task.Run(() => DrainAsync(l, stoppingToken), CancellationToken.None)).ToList();
        try
        {
            await foreach (var e in _queue.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
            {
                foreach (var lane in lanes)
                {
                    try
                    {
                        if (lane.Transport.Enabled)   // BUG-262: Enabled reads options, which can throw
                        {
                            lane.Add(e);
                            Report(lane);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "SIEM transport {Transport} couldn't take event {EventId}.", lane.Transport.Name, e.EventId);
                    }
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Shutting down.
        }
        finally
        {
            // A transport stuck in a send that ignores the stop isn't waited on for ever (its queue is left as it is).
            var all = Task.WhenAll(workers);
            if (await Task.WhenAny(all, Task.Delay(TimeSpan.FromSeconds(5), CancellationToken.None)).ConfigureAwait(false) == all)
                foreach (var lane in lanes) lane.Dispose();
        }
    }

    private void Report(Lane lane) =>
        _health?.RecordQueue(DeliveryHealth.Siem(lane.Transport.Name), lane.Dropped, lane.Depth);

    // One transport's worker: critical events first, then routine ones, one at a time, until shutdown.
    private async Task DrainAsync(Lane lane, CancellationToken ct)
    {
        long reported = 0;
        while (!ct.IsCancellationRequested)
        {
            SecurityEvent e;
            try { e = await lane.TakeAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            Report(lane);
            try
            {
                await lane.Transport.SendAsync(e, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "SIEM transport {Transport} threw for event {EventId}.", lane.Transport.Name, e.EventId);
            }
            if (lane.Dropped >= reported + 100 || (reported == 0 && lane.Dropped > 0))
            {
                reported = lane.Dropped;
                _logger.LogWarning("SIEM transport {Transport} is behind: dropped {Dropped} routine or oldest event(s).", lane.Transport.Name, reported);
            }
        }
    }
}
