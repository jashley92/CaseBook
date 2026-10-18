using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Notifications;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>CAP-10: the retention review's nightly count and monthly email, bound from <c>Notifications:RetentionReview</c>.</summary>
public sealed class RetentionReviewScanOptions
{
    /// <summary>Email the Legal / Privacy distribution once a month when cases are waiting. Off by default.</summary>
    public bool Email { get; set; }

    /// <summary>Hours between counts. Default 24 (0 also means 24); server-side only.</summary>
    public double IntervalHours { get; set; } = 24;
}

/// <summary>
/// CAP-10: once after startup and then every <see cref="RetentionReviewScanOptions.IntervalHours"/> (a day by default),
/// counts the closed cases past <c>Retention:CaseYears</c> for Diagnostics, and sends the monthly email to Legal when it's
/// on (<see cref="RetentionReviewScanner"/>). Only counts and tells (ADR 0004): it never archives or deletes. A change to
/// the retention setting counts again within a few minutes. Singleton; the scanner is scoped, so a new scope per run.
/// Mirrors <see cref="AccessLogRetentionHostedService"/> and <see cref="StaleCaseHostedService"/>.
/// </summary>
public sealed class RetentionReviewHostedService(IServiceScopeFactory scopeFactory, IOptionsMonitor<CaseRetentionOptions> retention,
    IOptionsMonitor<RetentionReviewScanOptions> options, ILogger<RetentionReviewHostedService> logger, IJobStatus? jobs = null)
    : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(5);

    /// <summary>CAP-29: this job's row on Diagnostics. Run now counts again (read-only); it never sends the email.</summary>
    public static readonly JobDefinition Job = new("retention-review", "Retention review count",
        "every IntervalHours (default 24 h), and when the setting changes", RunNow: true);

    private DateTimeOffset _lastRunUtc = DateTimeOffset.MinValue;
    private int? _lastYears;   // the settings the last count ran with: a change counts again at once
    private bool _lastEmail;

    // CAP-29: listed, with its Run now, when it's built, so the row is there before the first pass.
    private readonly IJobStatus? _jobs = Listed(jobs, new Counter(scopeFactory, retention, logger));

    private static IJobStatus? Listed(IJobStatus? jobs, Counter counter)
    {
        jobs?.Register(Job, counter.CountNowAsync);
        return jobs;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            // BUG-262: a setting that can't be read skips this pass; it doesn't stop the app.
            try
            {
                var years = retention.CurrentValue.CaseYears;
                var o = options.CurrentValue;
                if (years != _lastYears || o.Email != _lastEmail || DateTimeOffset.UtcNow - _lastRunUtc >= JobSchedule.Hours(o.IntervalHours, 24))
                    await RunAsync(years, o.Email, stoppingToken);
                _jobs?.Scheduled(Job, years > 0, _lastRunUtc == DateTimeOffset.MinValue
                    ? DateTimeOffset.UtcNow
                    : _lastRunUtc + JobSchedule.Hours(o.IntervalHours, 24));   // CAP-29
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Retention review count skipped: its settings couldn't be read.");
            }
            try { await Task.Delay(PollInterval, stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) { /* shutting down */ }
        }
    }

    private async Task RunAsync(int years, bool email, CancellationToken ct)
    {
        using var run = _jobs.Begin(Job);   // CAP-29: skipped while a Run now counts
        if (run is null) return;
        try
        {
            using var scope = scopeFactory.CreateScope();
            var (count, emailed) = await scope.ServiceProvider.GetRequiredService<RetentionReviewScanner>().ScanAsync(years, email, ct);
            _lastRunUtc = DateTimeOffset.UtcNow;
            _lastYears = years;
            _lastEmail = email;
            run.Succeeded(count.Due);
            if (emailed)
                logger.LogInformation("Retention review: told Legal that {Count} closed case(s) are past retention.", count.Due);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown in progress; nothing to log.
        }
        catch (Exception ex)
        {
            run.Failed(ex);
            logger.LogError(ex, "Retention review count failed; it will try again in a few minutes.");
        }
    }

    // CAP-29: Diagnostics' Run now: the count only (read-only, ADR 0004), never the monthly email; the schedule stays.
    private sealed class Counter(IServiceScopeFactory scopes, IOptionsMonitor<CaseRetentionOptions> retention, ILogger logger)
    {
        public async Task CountNowAsync(JobRun run, CancellationToken ct)
        {
            try
            {
                using var scope = scopes.CreateScope();
                var count = await scope.ServiceProvider.GetRequiredService<RetentionReviewScanner>().CountAsync(retention.CurrentValue.CaseYears, ct);
                run.Succeeded(count.Due);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { /* shutting down */ }
            catch (Exception ex)
            {
                run.Failed(ex);
                logger.LogError(ex, "Retention review count (run from Diagnostics) failed.");
            }
        }
    }
}
