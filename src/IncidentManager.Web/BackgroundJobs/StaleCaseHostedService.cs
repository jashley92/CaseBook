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

    private DateTimeOffset _lastRunUtc = DateTimeOffset.MinValue;

    public StaleCaseHostedService(IServiceScopeFactory scopeFactory,
        IOptionsMonitor<StaleCaseScanOptions> options, ILogger<StaleCaseHostedService> logger)
    {
        _scopeFactory = scopeFactory;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var options = _options.CurrentValue;
            if (options.Enabled && IsDue(options))
                await RunCycleAsync(options, stoppingToken);

            await DelayAsync(PollInterval, stoppingToken);
        }
    }

    private bool IsDue(StaleCaseScanOptions options)
    {
        if (_lastRunUtc == DateTimeOffset.MinValue) return true; // first pass after startup
        var interval = TimeSpan.FromHours(options.IntervalHours > 0 ? options.IntervalHours : 12);
        return DateTimeOffset.UtcNow - _lastRunUtc >= interval;
    }

    private static async Task DelayAsync(TimeSpan delay, CancellationToken ct)
    {
        try { await Task.Delay(delay, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { /* shutting down */ }
    }

    private async Task RunCycleAsync(StaleCaseScanOptions options, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var scanner = scope.ServiceProvider.GetRequiredService<StaleCaseScanner>();

            var thresholds = new StaleThresholdDays(
                options.Days.Informational, options.Days.Low, options.Days.Medium,
                options.Days.High, options.Days.Critical);

            var notified = await scanner.ScanAndNotifyAsync(thresholds, ct);
            _lastRunUtc = DateTimeOffset.UtcNow;

            if (notified > 0)
                _logger.LogInformation("Stale-case scan: sent {Count} nudge(s).", notified);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Stale-case scan cycle failed.");
        }
    }
}
