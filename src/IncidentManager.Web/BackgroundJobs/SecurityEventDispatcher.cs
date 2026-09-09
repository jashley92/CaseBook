using IncidentManager.Infrastructure.Siem;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Drains the <see cref="SecurityEventQueue"/> and fans each security event out to every enabled
/// transport (webhook, syslog, …) (F-18). Delivery is best-effort: each transport call is guarded so one
/// failing transport never stops the others, and nothing here throws out of the loop. The audit chain
/// remains the system of record, so a dropped event is not a data-integrity concern.
/// </summary>
public sealed class SecurityEventDispatcher : BackgroundService
{
    private readonly SecurityEventQueue _queue;
    private readonly IReadOnlyList<ISecurityEventTransport> _transports;
    private readonly ILogger<SecurityEventDispatcher> _logger;

    public SecurityEventDispatcher(SecurityEventQueue queue, IEnumerable<ISecurityEventTransport> transports,
        ILogger<SecurityEventDispatcher> logger)
    {
        _queue = queue;
        _transports = transports.ToList();
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var e in _queue.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
            {
                foreach (var t in _transports)
                {
                    if (!t.Enabled) continue;
                    try
                    {
                        await t.SendAsync(e, stoppingToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                    {
                        return;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "SIEM transport {Transport} threw for event {EventId}.", t.Name, e.EventId);
                    }
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Shutting down.
        }
    }
}
