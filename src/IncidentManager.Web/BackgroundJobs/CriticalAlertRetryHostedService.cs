using IncidentManager.Application.Abstractions;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// BUG-101: every minute, tries again the breach-escalation and integrity-alarm emails whose send failed and whose next
/// try is due (<see cref="ICriticalAlertOutbox"/>). Always on: these are the emails that mustn't be lost. Writes only
/// the outbox's own rows, never case data.
/// </summary>
public sealed class CriticalAlertRetryHostedService(ICriticalAlertOutbox outbox, ILogger<CriticalAlertRetryHostedService> logger,
    IJobStatus? jobs = null) : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(1);

    /// <summary>CAP-29: this job's row on Diagnostics; its items are the alert emails delivered on retry.</summary>
    public static readonly JobDefinition Job = new("critical-alert-retry", "Alert email retry", "every minute");

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        jobs?.Register(Job);
        while (!stoppingToken.IsCancellationRequested)
        {
            jobs?.Scheduled(Job, true, DateTimeOffset.UtcNow + PollInterval);
            JobRun? run = null;
            try
            {
                await Task.Delay(PollInterval, stoppingToken).ConfigureAwait(false);
                run = jobs.Begin(Job);   // CAP-29
                var sent = await outbox.RetryDueAsync(stoppingToken);
                run?.Succeeded(sent);
                if (sent > 0) logger.LogInformation("Delivered {Count} alert email(s) on retry.", sent);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
            // BUG-262: the email settings are read before the retry's own guard; a failure there is tried again next minute.
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                run?.Failed(ex);
                logger.LogError(ex, "Retrying undelivered alert emails failed.");
            }
            run?.Dispose();
        }
    }
}
