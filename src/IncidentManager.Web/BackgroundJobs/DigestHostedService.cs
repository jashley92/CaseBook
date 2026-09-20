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

    private DateTimeOffset _lastRunUtc = DateTimeOffset.MinValue;

    public DigestHostedService(IServiceScopeFactory scopeFactory,
        IOptionsMonitor<DigestScanOptions> options, ILogger<DigestHostedService> logger)
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

    private bool IsDue(DigestScanOptions options)
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
            var scanner = scope.ServiceProvider.GetRequiredService<DigestScanner>();

            var sent = await scanner.ScanAndNotifyAsync(ct);
            _lastRunUtc = DateTimeOffset.UtcNow;

            if (sent > 0)
                _logger.LogInformation("Work-digest scan: sent {Count} digest(s).", sent);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Work-digest scan cycle failed.");
        }
    }
}
