using IncidentManager.Application.Abstractions;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// BUG-101: every minute, tries again the breach-escalation and integrity-alarm emails whose send failed and whose next
/// try is due (<see cref="ICriticalAlertOutbox"/>). Always on: these are the emails that mustn't be lost. Writes only
/// the outbox's own rows, never case data.
/// </summary>
public sealed class CriticalAlertRetryHostedService(ICriticalAlertOutbox outbox, ILogger<CriticalAlertRetryHostedService> logger)
    : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(PollInterval, stoppingToken).ConfigureAwait(false);
                var sent = await outbox.RetryDueAsync(stoppingToken);
                if (sent > 0) logger.LogInformation("Delivered {Count} alert email(s) on retry.", sent);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        }
    }
}
