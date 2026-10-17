using IncidentManager.Application.Access;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>The <c>Retention</c> settings the background jobs read.</summary>
public sealed class RetentionOptions
{
    /// <summary>PROD-52: years the access log is kept (0 keeps it forever).</summary>
    public int AccessLogYears { get; set; } = 3;
}

/// <summary>
/// PROD-52: once a day (and once after startup), deletes access-log entries older than <c>Retention:AccessLogYears</c>
/// (<see cref="AccessLogRetention"/>). Polls the setting every few minutes, so a change applies without a restart.
/// Singleton hosted service; the retention service is scoped, so a new scope is created per run.
/// </summary>
public sealed class AccessLogRetentionHostedService(IServiceScopeFactory scopeFactory, IOptionsMonitor<RetentionOptions> options,
    ILogger<AccessLogRetentionHostedService> logger) : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(5);

    private DateOnly? _lastRunDay;   // the UTC day of the last successful run
    private int? _lastYears;         // and the setting it ran with: a change runs again the same day

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            // BUG-262: a setting that can't be read skips this pass; it doesn't stop the app.
            try
            {
                var years = options.CurrentValue.AccessLogYears;
                var today = DateOnly.FromDateTime(DateTime.UtcNow);
                if (today != _lastRunDay || years != _lastYears)
                    await RunAsync(years, today, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Access log retention skipped: its setting couldn't be read.");
            }
            try { await Task.Delay(PollInterval, stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) { /* shutting down */ }
        }
    }

    private async Task RunAsync(int years, DateOnly today, CancellationToken ct)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            await scope.ServiceProvider.GetRequiredService<AccessLogRetention>().PruneAsync(years, ct);
            _lastRunDay = today;
            _lastYears = years;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Access log retention failed; it will try again in a few minutes.");
        }
    }
}
