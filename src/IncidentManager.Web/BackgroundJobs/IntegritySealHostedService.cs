using IncidentManager.Application.Integrity;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Continuously verifies the audit hash-chain — the internal links <b>and</b> the most-covering signed
/// seal (S-05) — and, when it is intact and a seal is due, records a fresh signed seal. Verification and
/// the F-16 alarm (SIEM/critical log + email + in-app banner) run on a fixed short cadence
/// (<see cref="VerifyPoll"/>) regardless of the seal interval and of whether sealing is enabled, so a
/// tamper is caught within minutes rather than at the next seal. Sealing is gated by
/// <c>AutoSeal:Enabled</c> and spaced by <c>AutoSeal:IntervalHours</c> (which now only bounds how much
/// recent history is not yet sealed, not detection latency). Runs a cycle immediately at startup so the
/// banner reflects the true state after a restart. Singleton hosted service; <see cref="IntegrityService"/>
/// is scoped, so a new scope is created per cycle.
/// </summary>
public sealed class IntegritySealHostedService : BackgroundService
{
    // Verification (chain + latest seal) and the alarm run on this cadence regardless of the seal
    // interval, so detection latency is decoupled from — and far shorter than — how often we seal. Full
    // re-verification is O(n) over the audit log; 10 minutes balances detection latency against load.
    private static readonly TimeSpan VerifyPoll = TimeSpan.FromMinutes(10);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IOptionsMonitor<AutoSealOptions> _options;
    private readonly ILogger<IntegritySealHostedService> _logger;

    public IntegritySealHostedService(IServiceScopeFactory scopeFactory, IOptionsMonitor<AutoSealOptions> options,
        ILogger<IntegritySealHostedService> logger)
    {
        _scopeFactory = scopeFactory;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            // Read options each loop so administered Enabled/IntervalHours changes take effect at runtime
            // (they flow in via the DB settings provider + IOptionsMonitor).
            await RunCycleAsync(_options.CurrentValue, stoppingToken);
            await DelayAsync(VerifyPoll, stoppingToken);
        }
    }

    private static async Task DelayAsync(TimeSpan delay, CancellationToken ct)
    {
        try { await Task.Delay(delay, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { /* shutting down */ }
    }

    private async Task RunCycleAsync(AutoSealOptions options, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var integrity = scope.ServiceProvider.GetRequiredService<IntegrityService>();

            // Always verify (chain + most-covering seal), record the app-wide status, and fire the F-16
            // alarm once on a fresh break. Never seal over a broken chain.
            var verification = await integrity.VerifyAndTrackAsync(ct);
            if (!verification.IsValid || !options.Enabled) return;

            // Seal only when the interval has elapsed since the last seal; the verify cadence above is
            // independent, so a longer interval just widens the (DB-write-only forgeable) unsealed tail.
            var interval = TimeSpan.FromHours(options.IntervalHours > 0 ? options.IntervalHours : 6);
            var seal = await integrity.SealIfDueAsync(interval, ct);
            if (seal is not null)
                _logger.LogInformation("Recorded integrity seal up to sequence {UpToSequence}.", seal.UpToSequence);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Auto-seal background job cycle failed.");
        }
    }
}
