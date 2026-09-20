using IncidentManager.Application.Notifications;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Periodically scans for cases whose regulatory notification deadline (PROD-07) is approaching or passed and
/// reminds each case's incident commander + assignees (PROD-37), once per band. Gated by
/// <c>Notifications:DeadlineScan:Enabled</c> (off by default) and by the deadline clock itself; paced by
/// <c>IntervalHours</c>. Read-only over case data — it records nothing and never changes case state, so it
/// stays out of the audit chain.
///
/// Singleton hosted service; <see cref="NotificationDeadlineScanner"/> is scoped, so a new scope is created
/// per cycle. Mirrors <see cref="OverdueActionItemHostedService"/> / <see cref="DueSoonActionItemHostedService"/>.
/// </summary>
public sealed class NotificationDeadlineHostedService : BackgroundService
{
    // Re-read options this often so an admin toggling the job on/off takes effect within a few minutes,
    // independent of the (slower) scan interval.
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(5);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IOptionsMonitor<DeadlineReminderScanOptions> _options;
    private readonly ILogger<NotificationDeadlineHostedService> _logger;

    private DateTimeOffset _lastRunUtc = DateTimeOffset.MinValue;

    public NotificationDeadlineHostedService(IServiceScopeFactory scopeFactory,
        IOptionsMonitor<DeadlineReminderScanOptions> options, ILogger<NotificationDeadlineHostedService> logger)
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
                await RunCycleAsync(stoppingToken);

            await DelayAsync(PollInterval, stoppingToken);
        }
    }

    private bool IsDue(DeadlineReminderScanOptions options)
    {
        if (_lastRunUtc == DateTimeOffset.MinValue) return true; // first pass after startup
        var interval = TimeSpan.FromHours(options.IntervalHours > 0 ? options.IntervalHours : 1);
        return DateTimeOffset.UtcNow - _lastRunUtc >= interval;
    }

    private static async Task DelayAsync(TimeSpan delay, CancellationToken ct)
    {
        try { await Task.Delay(delay, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { /* shutting down */ }
    }

    private async Task RunCycleAsync(CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var scanner = scope.ServiceProvider.GetRequiredService<NotificationDeadlineScanner>();

            var notified = await scanner.ScanAndNotifyAsync(ct);
            _lastRunUtc = DateTimeOffset.UtcNow;

            if (notified > 0)
                _logger.LogInformation("Regulatory notification-deadline scan: sent {Count} reminder(s).", notified);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Regulatory notification-deadline scan cycle failed.");
        }
    }
}
