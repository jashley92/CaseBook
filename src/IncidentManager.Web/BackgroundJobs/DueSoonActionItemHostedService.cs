using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Notifications;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Periodically scans for after-action items due within the lead window and emails a reminder to each item's
/// owner (E-03d), once per item ahead of the deadline. Gated by <c>Notifications:DueSoonScan:Enabled</c> (off
/// by default) and paced by <c>IntervalHours</c>. Read-only over case data — it records nothing, so it stays
/// out of the audit chain.
///
/// Singleton hosted service; <see cref="DueSoonActionItemScanner"/> is scoped, so a new scope is created per
/// cycle. Mirrors <see cref="OverdueActionItemHostedService"/>.
/// </summary>
public sealed class DueSoonActionItemHostedService : BackgroundService
{
    // Re-read options this often so an admin toggling the job on/off takes effect within a few minutes,
    // independent of the (much slower) scan interval.
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(5);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IOptionsMonitor<DueSoonScanOptions> _options;
    private readonly ILogger<DueSoonActionItemHostedService> _logger;

    private readonly IJobStatus? _jobs;   // CAP-29: last run, next due and last error, for Diagnostics

    private DateTimeOffset _lastRunUtc = DateTimeOffset.MinValue;

    /// <summary>CAP-29: this job's row on Diagnostics.</summary>
    public static readonly JobDefinition Job = new("due-soon-actions", "Due-soon after-action reminders", "every IntervalHours (default 6 h), when on");

    public DueSoonActionItemHostedService(IServiceScopeFactory scopeFactory,
        IOptionsMonitor<DueSoonScanOptions> options, ILogger<DueSoonActionItemHostedService> logger, IJobStatus? jobs = null)
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
                _logger.LogError(ex, "Due-soon scan skipped: its settings couldn't be read.");
            }

            await DelayAsync(PollInterval, stoppingToken);
        }
    }

    private bool IsDue(DueSoonScanOptions options)
    {
        if (_lastRunUtc == DateTimeOffset.MinValue) return true; // first pass after startup
        var interval = JobSchedule.Hours(options.IntervalHours, 6);
        return DateTimeOffset.UtcNow - _lastRunUtc >= interval;
    }

    // CAP-29: when the next pass is due (it runs at the first poll after); the first runs at once.
    private DateTimeOffset NextDue(DueSoonScanOptions options) =>
        _lastRunUtc == DateTimeOffset.MinValue ? DateTimeOffset.UtcNow : _lastRunUtc + JobSchedule.Hours(options.IntervalHours, 6);

    private static async Task DelayAsync(TimeSpan delay, CancellationToken ct)
    {
        try { await Task.Delay(delay, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { /* shutting down */ }
    }

    private async Task RunCycleAsync(DueSoonScanOptions options, CancellationToken ct)
    {
        using var run = _jobs.Begin(Job);   // CAP-29
        if (run is null) return;
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var scanner = scope.ServiceProvider.GetRequiredService<DueSoonActionItemScanner>();

            var notified = await scanner.ScanAndNotifyAsync(options.LeadHours, ct);
            _lastRunUtc = DateTimeOffset.UtcNow;
            run.Succeeded(notified);

            if (notified > 0)
                _logger.LogInformation("Due-soon after-action scan: sent {Count} reminder(s).", notified);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            run.Failed(ex);
            _logger.LogError(ex, "Due-soon after-action scan cycle failed.");
        }
    }
}
