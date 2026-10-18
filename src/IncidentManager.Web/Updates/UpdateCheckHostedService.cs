using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.Updates;

/// <summary>
/// Runs the update check (PROD-49) a couple of minutes after start, then every <c>Updates:CheckIntervalHours</c>
/// while <c>Updates:CheckEnabled</c> is on. Mirrors <see cref="BackgroundJobs.StaleCaseHostedService"/>: options are
/// re-read every few minutes, so turning the check on takes effect without a restart.
/// </summary>
public sealed class UpdateCheckHostedService : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan FirstDelay = TimeSpan.FromMinutes(2);   // never during start-up
    private const int MinimumIntervalHours = 6;
    private const int MaximumIntervalHours = 168;   // the setting's own limit

    private readonly UpdateCheckService _updates;
    private readonly IOptionsMonitor<UpdateCheckOptions> _options;
    private readonly ILogger<UpdateCheckHostedService> _logger;
    private readonly IJobStatus? _jobs;   // CAP-29: last run, next due and last error, for Diagnostics
    private DateTimeOffset _lastRunUtc = DateTimeOffset.MinValue;

    /// <summary>CAP-29: this job's row on Diagnostics (Administration › Updates has its own Check now).</summary>
    public static readonly JobDefinition Job = new("update-check", "Update check", "every Updates:CheckIntervalHours (6 to 168 h), when on");

    public UpdateCheckHostedService(UpdateCheckService updates, IOptionsMonitor<UpdateCheckOptions> options,
        ILogger<UpdateCheckHostedService> logger, IJobStatus? jobs = null)
    {
        _jobs = jobs;
        jobs?.Register(Job);
        _updates = updates;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await DelayAsync(FirstDelay, stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            JobRun? run = null;
            try
            {
                // BUG-262: read inside the guard, so a setting that can't be read skips this pass instead of stopping the app.
                var o = _options.CurrentValue;
                if (o.CheckEnabled && IsDue(o) && (run = _jobs.Begin(Job)) is not null)
                {
                    var status = await _updates.CheckAsync(manual: false, stoppingToken);
                    _lastRunUtc = DateTimeOffset.UtcNow;
                    if (status.State == UpdateState.Failed) run.Failed("Check failed");   // why: Administration › Updates
                    else run.Succeeded(status.Releases.Count);
                }
                _jobs?.Scheduled(Job, o.CheckEnabled, _lastRunUtc == DateTimeOffset.MinValue ? DateTimeOffset.UtcNow : _lastRunUtc + Interval(o));
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { /* shutting down */ }
            catch (Exception ex)
            {
                run?.Failed(ex);
                _logger.LogError(ex, "Update check cycle failed.");
                _lastRunUtc = DateTimeOffset.UtcNow;
            }
            run?.Dispose();
            await DelayAsync(PollInterval, stoppingToken);
        }
    }

    private bool IsDue(UpdateCheckOptions o)
    {
        if (_lastRunUtc == DateTimeOffset.MinValue) return true;
        return DateTimeOffset.UtcNow - _lastRunUtc >= Interval(o);
    }

    private static TimeSpan Interval(UpdateCheckOptions o) =>
        TimeSpan.FromHours(Math.Clamp(o.CheckIntervalHours > 0 ? o.CheckIntervalHours : 24, MinimumIntervalHours, MaximumIntervalHours));

    private static async Task DelayAsync(TimeSpan delay, CancellationToken ct)
    {
        try { await Task.Delay(delay, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { /* shutting down */ }
    }
}
