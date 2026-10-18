using IncidentManager.Application.Abstractions;
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
    ILogger<AccessLogRetentionHostedService> logger, IJobStatus? jobs = null) : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(5);

    /// <summary>CAP-29: this job's row on Diagnostics.</summary>
    public static readonly JobDefinition Job = new("access-log-retention", "Access log retention", "daily (UTC), and when the setting changes");

    /// <summary>CAP-29/CAP-31: the import queue's step has a row of its own.</summary>
    public static readonly JobDefinition ImportJob = new("decided-import-retention", "Decided import retention",
        "daily (UTC), and when the setting changes");

    // Per step: the UTC day of its last successful run, and the setting it ran with (a change runs it again the same day).
    private DateOnly? _lastRunDay, _lastImportRunDay;
    private int? _lastYears, _lastImportDays;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        jobs?.Register(Job);
        jobs?.Register(ImportJob);
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
                // CAP-29: the next UTC day's first poll; 0 keeps everything, so that step is off.
                var tomorrow = new DateTimeOffset(today.AddDays(1).ToDateTime(TimeOnly.MinValue), TimeSpan.Zero);
                jobs?.Scheduled(Job, current.AccessLogYears > 0, _lastRunDay == today ? tomorrow : DateTimeOffset.UtcNow);
                jobs?.Scheduled(ImportJob, current.DecidedImportDays > 0, _lastImportRunDay == today ? tomorrow : DateTimeOffset.UtcNow);
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
        using var run = jobs.Begin(Job);   // CAP-29
        if (run is null) return;
        try
        {
            using var scope = scopeFactory.CreateScope();
            var deleted = await scope.ServiceProvider.GetRequiredService<AccessLogRetention>().PruneAsync(years, ct);
            _lastRunDay = today;
            _lastYears = years;
            run.Succeeded(deleted);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            run.Failed(ex);
            logger.LogError(ex, "Access log retention failed; it will try again in a few minutes.");
        }
    }

    // CAP-31: the import queue's step, as the access log's.
    private async Task RunImportsAsync(int days, DateOnly today, CancellationToken ct)
    {
        using var run = jobs.Begin(ImportJob);   // CAP-29
        if (run is null) return;
        try
        {
            using var scope = scopeFactory.CreateScope();
            var cleared = await scope.ServiceProvider.GetRequiredService<DecidedImportRetention>().ClearAsync(days, ct);
            _lastImportRunDay = today;
            _lastImportDays = days;
            run.Succeeded(cleared);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            run.Failed(ex);
            logger.LogError(ex, "Import retention failed; it will try again in a few minutes.");
        }
    }
}
