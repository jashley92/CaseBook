using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Periodically re-hashes evidence at rest and raises the F-17 drift alarm (SIEM/critical log + email +
/// in-app banner) when stored bytes no longer match their recorded SHA-256. Runs at startup, then once in every
/// <c>Integrity:EvidenceVerify:IntervalHours</c> interval (counted from midnight UTC). PROD-53: each run re-hashes one
/// share of the files, so that every file is checked at least once in <c>Integrity:EvidenceVerify:PassDays</c> days and a
/// large store isn't read end to end every run. Gated by <c>Integrity:EvidenceVerify:Enabled</c> (off by default).
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

    private readonly IJobStatus? _jobs;   // CAP-29: last run, next due and last error, for Diagnostics

    private long? _lastSlot;   // the interval the last run was in (PROD-53: one run per interval)

    /// <summary>
    /// CAP-29: this job's row on Diagnostics. Run now re-hashes the current interval's share again: a read-only scan (it
    /// raises the drift alarm as a scheduled run would), and the schedule stays as it was.
    /// </summary>
    public static readonly JobDefinition Job = new("evidence-verify", "Evidence re-verification",
        "one share every IntervalHours (default 24 h), when on", RunNow: true);

    public EvidenceIntegrityHostedService(IServiceScopeFactory scopeFactory,
        IOptionsMonitor<EvidenceVerifyOptions> options, ILogger<EvidenceIntegrityHostedService> logger, IJobStatus? jobs = null)
    {
        _scopeFactory = scopeFactory;
        _options = options;
        _logger = logger;
        _jobs = jobs;
        jobs?.Register(Job, RunNowAsync);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            // BUG-262: a setting that can't be read (a typo in the settings file) skips this pass; it doesn't stop the app.
            try
            {
                var options = _options.CurrentValue;
                var interval = JobSchedule.Hours(options.IntervalHours, 24);
                var slot = EvidenceIntegrityVerifier.Slot(DateTimeOffset.UtcNow, interval);
                if (options.Enabled && slot != _lastSlot)   // the first run after startup, then one per interval
                    await RunCycleAsync(options, interval, slot, stoppingToken);
                // CAP-29: the next interval's start (counted from midnight UTC), or now while this one's run is owed.
                _jobs?.Scheduled(Job, options.Enabled,
                    slot == _lastSlot ? EvidenceIntegrityVerifier.SlotStart(slot + 1, interval) : DateTimeOffset.UtcNow);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Evidence re-verification skipped: its settings couldn't be read.");
            }

            // Poll on a short fixed cadence and decide per-tick whether a full pass is due, so runtime
            // Enabled/IntervalHours changes are picked up without restarting the app.
            await DelayAsync(PollInterval, stoppingToken);
        }
    }

    private static async Task DelayAsync(TimeSpan delay, CancellationToken ct)
    {
        try { await Task.Delay(delay, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { /* shutting down */ }
    }

    // CAP-29: Diagnostics' Run now: this interval's share, as the scheduled run checks it; _lastSlot is left alone.
    private async Task RunNowAsync(JobRun run, CancellationToken ct)
    {
        var options = _options.CurrentValue;
        var interval = JobSchedule.Hours(options.IntervalHours, 24);
        await VerifyAsync(run, options, interval, EvidenceIntegrityVerifier.Slot(DateTimeOffset.UtcNow, interval), manual: true, ct);
    }

    private async Task RunCycleAsync(EvidenceVerifyOptions options, TimeSpan interval, long slot, CancellationToken ct)
    {
        using var run = _jobs.Begin(Job);   // CAP-29: skipped while a Run now re-hashes
        if (run is null) return;
        await VerifyAsync(run, options, interval, slot, manual: false, ct);
    }

    private async Task VerifyAsync(JobRun run, EvidenceVerifyOptions options, TimeSpan interval, long slot, bool manual, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var verifier = scope.ServiceProvider.GetRequiredService<EvidenceIntegrityVerifier>();

            var shares = EvidenceIntegrityVerifier.Shares(options.PassDays, interval);
            var share = (int)(slot % shares);
            var result = await verifier.VerifyAndTrackAsync(share, shares, ct);
            if (!manual) _lastSlot = slot;
            run.Succeeded(result.CheckedCount);

            if (result.IsClean)
                _logger.LogInformation("Evidence-at-rest verification passed: {CheckedCount} of {TotalCount} item(s) checked " +
                                       "(share {Share} of {Shares}) match their recorded hash.",
                    result.CheckedCount, result.TotalCount, share + 1, shares);
            // A drift already raised the critical alarm inside VerifyAndTrackAsync; no extra logging here.
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            run.Failed(ex);
            _logger.LogError(ex, "Evidence-at-rest verification background job cycle failed.");
        }
    }
}
