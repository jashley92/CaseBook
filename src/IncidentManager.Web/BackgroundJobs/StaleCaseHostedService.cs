using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Notifications;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Periodically scans for open cases that have gone quiet past their severity's threshold and nudges each
/// case's incident commander + assignees (PROD-38). Gated by <c>Notifications:StaleScan:Enabled</c> (off by
/// default) and paced by <c>IntervalHours</c>. Read-only over case data — it records nothing and never
/// changes case state, so it stays out of the audit chain.
///
/// Singleton hosted service; <see cref="StaleCaseScanner"/> is scoped, so a new scope is created per cycle.
/// Mirrors <see cref="OverdueActionItemHostedService"/> / <see cref="NotificationDeadlineHostedService"/>.
/// </summary>
public sealed class StaleCaseHostedService : BackgroundService
{
    // Re-read options this often so an admin toggling the job on/off takes effect within a few minutes,
    // independent of the (slower) scan interval.
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(5);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IOptionsMonitor<StaleCaseScanOptions> _options;
    private readonly ILogger<StaleCaseHostedService> _logger;

    private readonly IJobStatus? _jobs;   // CAP-29: last run, next due and last error, for Diagnostics

    private DateTimeOffset _lastRunUtc = DateTimeOffset.MinValue;

    /// <summary>CAP-29: this job's row on Diagnostics.</summary>
    public static readonly JobDefinition Job = new("stale-cases", "Stale-case nudges", "every IntervalHours (default 12 h), when on");

    public StaleCaseHostedService(IServiceScopeFactory scopeFactory,
        IOptionsMonitor<StaleCaseScanOptions> options, ILogger<StaleCaseHostedService> logger, IJobStatus? jobs = null)
    {
        _jobs = jobs;
        jobs?.Register(Job);
        _scopeFactory = scopeFactory;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            // BUG-262: a setting that can't be read (a typo in the settings file) skips this pass; it doesn't stop the app.
            try
            {
                var options = _options.CurrentValue;
                if (options.Enabled && IsDue(options))
                    await RunCycleAsync(options, stoppingToken);
                _jobs?.Scheduled(Job, options.Enabled, NextDue(options));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Stale-case scan skipped: its settings couldn't be read.");
            }

            await DelayAsync(PollInterval, stoppingToken);
        }
    }

    private bool IsDue(StaleCaseScanOptions options)
    {
        if (_lastRunUtc == DateTimeOffset.MinValue) return true; // first pass after startup
        var interval = JobSchedule.Hours(options.IntervalHours, 12);
        return DateTimeOffset.UtcNow - _lastRunUtc >= interval;
    }

    // CAP-29: when the next pass is due (it runs at the first poll after); the first runs at once.
    private DateTimeOffset NextDue(StaleCaseScanOptions options) =>
        _lastRunUtc == DateTimeOffset.MinValue ? DateTimeOffset.UtcNow : _lastRunUtc + JobSchedule.Hours(options.IntervalHours, 12);

    private static async Task DelayAsync(TimeSpan delay, CancellationToken ct)
    {
        try { await Task.Delay(delay, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { /* shutting down */ }
    }

    private async Task RunCycleAsync(StaleCaseScanOptions options, CancellationToken ct)
    {
        using var run = _jobs.Begin(Job);   // CAP-29
        if (run is null) return;
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var scanner = scope.ServiceProvider.GetRequiredService<StaleCaseScanner>();

            var thresholds = new StaleThresholdDays(
                options.Days.Informational, options.Days.Low, options.Days.Medium,
                options.Days.High, options.Days.Critical);

            var notified = await scanner.ScanAndNotifyAsync(thresholds, ct);
            _lastRunUtc = DateTimeOffset.UtcNow;
            run.Succeeded(notified);

            if (notified > 0)
                _logger.LogInformation("Stale-case scan: sent {Count} nudge(s).", notified);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            run.Failed(ex);
            _logger.LogError(ex, "Stale-case scan cycle failed.");
        }
    }
}
