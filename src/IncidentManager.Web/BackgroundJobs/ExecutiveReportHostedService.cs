using IncidentManager.Application.Notifications;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>PROD-15: the scheduled executive report, bound from <c>Notifications:ExecutiveReport</c>. Off by default.</summary>
public sealed class ExecutiveReportOptions
{
    public bool Enabled { get; set; }
}

/// <summary>
/// Checks hourly whether last quarter's executive report is due (the first week of a new quarter) and sends it
/// once. Read-only over case data; never changes case state. Singleton; the scanner is scoped, so a new scope is
/// created per check. Mirrors <see cref="DigestHostedService"/>.
/// </summary>
public sealed class ExecutiveReportHostedService : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromHours(1);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IOptionsMonitor<ExecutiveReportOptions> _options;
    private readonly ILogger<ExecutiveReportHostedService> _logger;

    public ExecutiveReportHostedService(IServiceScopeFactory scopeFactory,
        IOptionsMonitor<ExecutiveReportOptions> options, ILogger<ExecutiveReportHostedService> logger)
    {
        _scopeFactory = scopeFactory;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            if (_options.CurrentValue.Enabled)
                await RunCycleAsync(stoppingToken);
            try { await Task.Delay(PollInterval, stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) { /* shutting down */ }
        }
    }

    private async Task RunCycleAsync(CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var scanner = scope.ServiceProvider.GetRequiredService<ExecutiveReportScanner>();
            if (await scanner.ScanAndSendAsync(ct))
                _logger.LogInformation("Executive report sent for the previous quarter.");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Executive report cycle failed.");
        }
    }
}
