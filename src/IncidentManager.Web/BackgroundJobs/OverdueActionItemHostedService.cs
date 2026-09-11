using IncidentManager.Application.Notifications;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Periodically scans for overdue after-action items and emails a reminder to each item's owner (E-03b),
/// once per item. Gated by <c>Notifications:OverdueScan:Enabled</c> (off by default) and paced by
/// <c>IntervalHours</c>. Read-only over case data — it records nothing, so it stays out of the audit chain.
///
/// Singleton hosted service; <see cref="OverdueActionItemScanner"/> is scoped, so a new scope is created per
/// cycle. Mirrors <see cref="EvidenceIntegrityHostedService"/> / <see cref="IntegritySealHostedService"/>.
/// </summary>
public sealed class OverdueActionItemHostedService : BackgroundService
{
    // Re-read options this often so an admin toggling the job on/off takes effect within a few minutes,
    // independent of the (much slower) scan interval.
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(5);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IOptionsMonitor<OverdueScanOptions> _options;
    private readonly ILogger<OverdueActionItemHostedService> _logger;

    private DateTimeOffset _lastRunUtc = DateTimeOffset.MinValue;

    public OverdueActionItemHostedService(IServiceScopeFactory scopeFactory,
        IOptionsMonitor<OverdueScanOptions> options, ILogger<OverdueActionItemHostedService> logger)
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

    private bool IsDue(OverdueScanOptions options)
    {
        if (_lastRunUtc == DateTimeOffset.MinValue) return true; // first pass after startup
        var interval = TimeSpan.FromHours(options.IntervalHours > 0 ? options.IntervalHours : 24);
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
            var scanner = scope.ServiceProvider.GetRequiredService<OverdueActionItemScanner>();

            var notified = await scanner.ScanAndNotifyAsync(ct);
            _lastRunUtc = DateTimeOffset.UtcNow;

            if (notified > 0)
                _logger.LogInformation("Overdue after-action scan: sent {Count} reminder(s).", notified);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Overdue after-action scan cycle failed.");
        }
    }
}
