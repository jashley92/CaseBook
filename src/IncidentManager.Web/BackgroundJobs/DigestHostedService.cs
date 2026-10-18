using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Notifications;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Periodically assembles and sends each opted-in user's consolidated work digest (PROD-39), once per period
/// (day/week) on their chosen cadence. Gated by <c>Notifications:DigestScan:Enabled</c> (off by default) and
/// paced by <c>IntervalHours</c>. Read-only over case data — it records nothing and never changes case state,
/// so it stays out of the audit chain.
///
/// Singleton hosted service; <see cref="DigestScanner"/> is scoped, so a new scope is created per cycle.
/// Mirrors <see cref="StaleCaseHostedService"/> / <see cref="NotificationDeadlineHostedService"/>.
/// </summary>
public sealed class DigestHostedService : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(5);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IOptionsMonitor<DigestScanOptions> _options;
    private readonly ILogger<DigestHostedService> _logger;

    private readonly IJobStatus? _jobs;   // CAP-29: last run, next due and last error, for Diagnostics

    private DateTimeOffset _lastRunUtc = DateTimeOffset.MinValue;

    /// <summary>CAP-29: this job's row on Diagnostics.</summary>
    public static readonly JobDefinition Job = new("digest", "Work digests", "every IntervalHours (default 1 h), when on");

    public DigestHostedService(IServiceScopeFactory scopeFactory,
        IOptionsMonitor<DigestScanOptions> options, ILogger<DigestHostedService> logger, IJobStatus? jobs = null)
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
                    await RunCycleAsync(stoppingToken);
                _jobs?.Scheduled(Job, options.Enabled, NextDue(options));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Digest scan skipped: its settings couldn't be read.");
            }

            await DelayAsync(PollInterval, stoppingToken);
        }
    }

    private bool IsDue(DigestScanOptions options)
    {
        if (_lastRunUtc == DateTimeOffset.MinValue) return true; // first pass after startup
        var interval = JobSchedule.Hours(options.IntervalHours, 1);
        return DateTimeOffset.UtcNow - _lastRunUtc >= interval;
    }

    // CAP-29: when the next pass is due (it runs at the first poll after); the first runs at once.
    private DateTimeOffset NextDue(DigestScanOptions options) =>
        _lastRunUtc == DateTimeOffset.MinValue ? DateTimeOffset.UtcNow : _lastRunUtc + JobSchedule.Hours(options.IntervalHours, 1);

    private static async Task DelayAsync(TimeSpan delay, CancellationToken ct)
    {
        try { await Task.Delay(delay, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { /* shutting down */ }
    }

    private async Task RunCycleAsync(CancellationToken ct)
    {
        using var run = _jobs.Begin(Job);   // CAP-29
        if (run is null) return;
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var scanner = scope.ServiceProvider.GetRequiredService<DigestScanner>();

            var sent = await scanner.ScanAndNotifyAsync(_options.CurrentValue.ImportWaitingHours, ct);   // CAP-01
            _lastRunUtc = DateTimeOffset.UtcNow;
            run.Succeeded(sent);

            if (sent > 0)
                _logger.LogInformation("Work-digest scan: sent {Count} digest(s).", sent);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            run.Failed(ex);
            _logger.LogError(ex, "Work-digest scan cycle failed.");
        }
    }
}
