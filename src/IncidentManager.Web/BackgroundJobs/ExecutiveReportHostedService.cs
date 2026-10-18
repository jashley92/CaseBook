using IncidentManager.Application.Abstractions;
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
    private readonly IJobStatus? _jobs;   // CAP-29: last run, next due and last error, for Diagnostics

    /// <summary>CAP-29: this job's row on Diagnostics; its items are the reports sent (one a quarter).</summary>
    public static readonly JobDefinition Job = new("executive-report", "Executive report", "hourly check, sent once a quarter, when on");

    public ExecutiveReportHostedService(IServiceScopeFactory scopeFactory,
        IOptionsMonitor<ExecutiveReportOptions> options, ILogger<ExecutiveReportHostedService> logger, IJobStatus? jobs = null)
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
            // BUG-262: a setting that can't be read skips this pass; it doesn't stop the app.
            try
            {
                var enabled = _options.CurrentValue.Enabled;
                if (enabled)
                    await RunCycleAsync(stoppingToken);
                _jobs?.Scheduled(Job, enabled, DateTimeOffset.UtcNow + PollInterval);   // CAP-29
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Executive report skipped: its settings couldn't be read.");
            }
            try { await Task.Delay(PollInterval, stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) { /* shutting down */ }
        }
    }

    private async Task RunCycleAsync(CancellationToken ct)
    {
        using var run = _jobs.Begin(Job);   // CAP-29
        if (run is null) return;
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var scanner = scope.ServiceProvider.GetRequiredService<ExecutiveReportScanner>();
            var sent = await scanner.ScanAndSendAsync(ct);
            run.Succeeded(sent ? 1 : 0);
            if (sent)
                _logger.LogInformation("Executive report sent for the previous quarter.");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex)
        {
            run.Failed(ex);
            _logger.LogError(ex, "Executive report cycle failed.");
        }
    }
}
