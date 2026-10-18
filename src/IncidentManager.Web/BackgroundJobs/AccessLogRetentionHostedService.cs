using IncidentManager.Application.Access;
using IncidentManager.Application.Import;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>The <c>Retention</c> settings the background jobs read.</summary>
public sealed class RetentionOptions
{
    /// <summary>PROD-52: years the access log is kept (0 keeps it forever).</summary>
    public int AccessLogYears { get; set; } = 3;

    /// <summary>CAP-31: days a decided import keeps its stored document (0 keeps it forever).</summary>
    public int DecidedImportDays { get; set; } = 90;
}

/// <summary>
/// PROD-52: once a day (and once after startup), deletes access-log entries older than <c>Retention:AccessLogYears</c>
/// (<see cref="AccessLogRetention"/>). CAP-31: and, as a second step, clears the stored documents of imports decided more
/// than <c>Retention:DecidedImportDays</c> ago (<see cref="DecidedImportRetention"/>). Each step runs on its own, so one
/// that fails doesn't hold up the other, and each is retried after a failure. Polls the settings every few minutes, so a
/// change applies without a restart. Singleton hosted service; the retention services are scoped, so a new scope is
/// created per run.
/// </summary>
public sealed class AccessLogRetentionHostedService(IServiceScopeFactory scopeFactory, IOptionsMonitor<RetentionOptions> options,
    ILogger<AccessLogRetentionHostedService> logger) : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(5);

    // Per step: the UTC day of its last successful run, and the setting it ran with (a change runs it again the same day).
    private DateOnly? _lastRunDay, _lastImportRunDay;
    private int? _lastYears, _lastImportDays;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            // BUG-262: a setting that can't be read skips this pass; it doesn't stop the app.
            try
            {
                var current = options.CurrentValue;
                var today = DateOnly.FromDateTime(DateTime.UtcNow);
                if (today != _lastRunDay || current.AccessLogYears != _lastYears)
                    await RunAsync(current.AccessLogYears, today, stoppingToken);
                if (today != _lastImportRunDay || current.DecidedImportDays != _lastImportDays)
                    await RunImportsAsync(current.DecidedImportDays, today, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Retention skipped: its settings couldn't be read.");
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

    // CAP-31: the import queue's step, as the access log's.
    private async Task RunImportsAsync(int days, DateOnly today, CancellationToken ct)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            await scope.ServiceProvider.GetRequiredService<DecidedImportRetention>().ClearAsync(days, ct);
            _lastImportRunDay = today;
            _lastImportDays = days;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Import retention failed; it will try again in a few minutes.");
        }
    }
}
