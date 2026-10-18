using IncidentManager.Application.Abstractions;
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
    // interval, so detection latency is decoupled from — and far shorter than — how often we seal. BUG-257: a cycle
    // hashes the entries written since the last one and checks every record; the whole chain is re-hashed every
    // IntegrityCheckState.FullEvery (6 h), so an edit to an old audit entry is found within that.
    internal static readonly TimeSpan VerifyPoll = TimeSpan.FromMinutes(10);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IOptionsMonitor<AutoSealOptions> _options;
    private readonly ILogger<IntegritySealHostedService> _logger;
    private readonly IntegrityCheckState _state;
    private readonly IJobStatus? _jobs;   // CAP-29: last run, next due and last error, for Diagnostics

    /// <summary>CAP-29: this job's row on Diagnostics (it may seal, so no Run now: Integrity's Verify now is the read).</summary>
    public static readonly JobDefinition Job = new("integrity", "Integrity check and seal",
        "check every 10 minutes (longer after a slow run); seal every AutoSeal:IntervalHours, when on");

    public IntegritySealHostedService(IServiceScopeFactory scopeFactory, IOptionsMonitor<AutoSealOptions> options,
        ILogger<IntegritySealHostedService> logger, IntegrityCheckState state, IJobStatus? jobs = null)
    {
        _state = state;
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
            // Read options each loop so administered Enabled/IntervalHours changes take effect at runtime
            // (they flow in via the DB settings provider + IOptionsMonitor).
            // BUG-262: a setting that can't be read skips this pass; it doesn't stop the app.
            try { await RunCycleAsync(_options.CurrentValue, stoppingToken); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Auto-seal skipped: its settings couldn't be read.");
            }
            // A slow check stretches the wait (IntegrityCheckState.NextWait), so it never takes most of the database's time.
            var wait = _state.NextWait(VerifyPoll);
            _jobs?.Scheduled(Job, true, DateTimeOffset.UtcNow + wait);   // CAP-29
            if (wait > VerifyPoll)
                _logger.LogWarning("The integrity check took {Seconds:N0} s, so the next one runs in {Minutes:N0} minutes instead of " +
                                   "{Poll:N0}: a change made outside CaseBook may take that long to be found.",
                    _state.LastCycle?.Total.TotalSeconds, wait.TotalMinutes, VerifyPoll.TotalMinutes);
            await DelayAsync(wait, stoppingToken);
        }
    }

    private static async Task DelayAsync(TimeSpan delay, CancellationToken ct)
    {
        try { await Task.Delay(delay, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { /* shutting down */ }
    }

    private async Task RunCycleAsync(AutoSealOptions options, CancellationToken ct)
    {
        using var run = _jobs.Begin(Job);   // CAP-29
        if (run is null) return;
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var integrity = scope.ServiceProvider.GetRequiredService<IntegrityService>();

            // Always verify (chain + most-covering seal), record the app-wide status, and fire the F-16
            // alarm once on a fresh break. Never seal over a broken chain.
            var verification = await integrity.MonitorAndTrackAsync(ct);
            if (!verification.IsValid || !options.Enabled)
            {
                run.Succeeded(_state.LastCycle?.RecordsChecked);   // the check ran; a break is the integrity card's
                return;
            }

            // Seal only when the interval has elapsed since the last seal; the verify cadence above is
            // independent, so a longer interval just widens the (DB-write-only forgeable) unsealed tail.
            var interval = JobSchedule.Hours(options.IntervalHours, 6);
            var seal = await integrity.SealIfDueAsync(interval, ct);
            run.Succeeded(_state.LastCycle?.RecordsChecked);
            if (seal is not null)
                _logger.LogInformation("Recorded integrity seal up to sequence {UpToSequence}.", seal.UpToSequence);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            run.Failed(ex);
            _logger.LogError(ex, "Auto-seal background job cycle failed.");
        }
    }
}
