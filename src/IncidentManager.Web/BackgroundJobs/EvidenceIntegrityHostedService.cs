using IncidentManager.Application.Integrity;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Periodically re-hashes evidence at rest and raises the F-17 drift alarm (SIEM/critical log + email +
/// in-app banner) when stored bytes no longer match their recorded SHA-256. Runs a pass immediately at
/// startup so the banner/panel reflects the true state after a restart, then every
/// <c>Integrity:EvidenceVerify:IntervalHours</c>. Gated by <c>Integrity:EvidenceVerify:Enabled</c>
/// (off by default): a full re-hash of the store is I/O-heavy, so it is opt-in and runs on a slow cadence.
///
/// Singleton hosted service; <see cref="EvidenceIntegrityVerifier"/> is scoped, so a new scope is created
/// per cycle. Mirrors <see cref="IntegritySealHostedService"/>.
/// </summary>
public sealed class EvidenceIntegrityHostedService : BackgroundService
{
    // How often we re-read options to see whether Enabled/IntervalHours changed at runtime. Independent of
    // the verification interval so an admin turning the job on takes effect within a few minutes.
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(5);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IOptionsMonitor<EvidenceVerifyOptions> _options;
    private readonly ILogger<EvidenceIntegrityHostedService> _logger;

    private DateTimeOffset _lastRunUtc = DateTimeOffset.MinValue;

    public EvidenceIntegrityHostedService(IServiceScopeFactory scopeFactory,
        IOptionsMonitor<EvidenceVerifyOptions> options, ILogger<EvidenceIntegrityHostedService> logger)
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

            // Poll on a short fixed cadence and decide per-tick whether a full pass is due, so runtime
            // Enabled/IntervalHours changes are picked up without restarting the app.
            await DelayAsync(PollInterval, stoppingToken);
        }
    }

    private bool IsDue(EvidenceVerifyOptions options)
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
            var verifier = scope.ServiceProvider.GetRequiredService<EvidenceIntegrityVerifier>();

            var result = await verifier.VerifyAndTrackAsync(ct);
            _lastRunUtc = DateTimeOffset.UtcNow;

            if (result.IsClean)
                _logger.LogInformation("Evidence-at-rest verification passed: {CheckedCount} item(s) match their recorded hash.",
                    result.CheckedCount);
            // A drift already raised the critical alarm inside VerifyAndTrackAsync; no extra logging here.
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Evidence-at-rest verification background job cycle failed.");
        }
    }
}
