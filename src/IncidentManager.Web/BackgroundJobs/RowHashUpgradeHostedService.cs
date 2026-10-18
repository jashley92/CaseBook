using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Integrity;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>Configuration for the integrity upgrade (C18, BUG-644), bound from <c>Integrity:Upgrade</c>.</summary>
public sealed class RowHashUpgradeOptions
{
    /// <summary>
    /// Minutes the app has been up and serving before the upgrade starts. Longer than the upgrade script's warm-up
    /// (Upgrade-CaseBook.ps1 waits up to 660 s for the new build to answer), so a build that fails its warm-up is rolled
    /// back before the upgrade has rewritten a row (BUG-645). 0 starts it as soon as the app serves.
    /// </summary>
    public double DelayMinutes { get; set; } = 15;
}

/// <summary>
/// BUG-644: runs the one-time integrity upgrade (<see cref="RowHashUpgrade"/>) in the background, once the app has been up
/// and serving for <see cref="RowHashUpgradeOptions.DelayMinutes"/>. It ran before start-up finished, so on a large
/// database the first start could pass IIS's 600 s start-up limit and the upgrade script's warm-up: a 500.37, a rollback,
/// and every retry the same. Until it has written its marker the record check is as before (lenient). It runs once a
/// start: a failure, or a shutdown part way, leaves what it recorded recorded, and the next start carries on.
/// </summary>
public sealed class RowHashUpgradeHostedService(
    IServiceScopeFactory scopes, IHostApplicationLifetime lifetime, IOptions<RowHashUpgradeOptions> options,
    ILogger<RowHashUpgradeHostedService> logger, IJobStatus? jobs = null) : BackgroundService
{
    /// <summary>CAP-29: this job's row on Diagnostics: off once the upgrade's marker is written.</summary>
    public static readonly JobDefinition Job = new("integrity-upgrade", "Integrity upgrade (one time)",
        "once, Integrity:Upgrade:DelayMinutes after start-up, until done");

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        jobs?.Register(Job);
        JobRun? run = null;
        try
        {
            await StartedAsync(stoppingToken);
            if (await UpgradedAsync(stoppingToken))
            {
                jobs?.Scheduled(Job, false, null);
                return;
            }
            var delay = TimeSpan.FromMinutes(Math.Max(0, options.Value.DelayMinutes));
            jobs?.Scheduled(Job, true, DateTimeOffset.UtcNow + delay);
            logger.LogInformation("The integrity upgrade starts in {Minutes:0.#} minute(s); until it finishes the record check is as before.",
                delay.TotalMinutes);
            await Task.Delay(delay, stoppingToken);
            run = jobs.Begin(Job);
            var recorded = await RunAsync(stoppingToken);
            run?.Succeeded(recorded);
            jobs?.Scheduled(Job, false, null);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            logger.LogInformation("The integrity upgrade stopped for the shutdown; it carries on at the next start.");
        }
        // A background service's exception would stop the app: every failure is logged instead, and tried at the next start.
        catch (Exception ex)
        {
            run?.Failed(ex);
            jobs?.Scheduled(Job, true, null);   // the next start tries again
            Log(ex);
        }
        finally
        {
            run?.Dispose();
        }
    }

    private async Task StartedAsync(CancellationToken ct)
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var registration = lifetime.ApplicationStarted.Register(() => started.TrySetResult());
        await started.Task.WaitAsync(ct);
    }

    private async Task<bool> UpgradedAsync(CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        return await RowIntegrityVerifier.UpgradedAsync(scope.ServiceProvider.GetRequiredService<AppDbContext>(), ct);
    }

    private async Task<long> RunAsync(CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        var started = DateTimeOffset.UtcNow;
        logger.LogInformation("Integrity upgrade started.");
        var upgrade = await RowHashUpgrade.RunAsync(scope.ServiceProvider.GetRequiredService<AppDbContext>(),
            scope.ServiceProvider.GetRequiredService<IHashChainService>(), scope.ServiceProvider.GetRequiredService<IClock>(), logger, ct);
        if (upgrade.Marked)
            logger.LogInformation("Integrity upgrade: recorded the hash of {Recorded} record(s) in {Minutes:0.#} minute(s); the record check is now strict.",
                upgrade.Recorded, (DateTimeOffset.UtcNow - started).TotalMinutes);
        foreach (var row in upgrade.Left.Take(50))
            logger.LogWarning("Integrity upgrade left {Record} unrecorded.", row);
        if (upgrade.Left.Count > 50)
            logger.LogWarning("Integrity upgrade left {More} more record(s) unrecorded.", upgrade.Left.Count - 50);
        // BUG-641: one it couldn't save keeps the check as it was until a later start records it.
        if (!upgrade.Marked && upgrade.Left.Count > 0)
            logger.LogWarning("The integrity upgrade couldn't record every record; the record check stays as before and the upgrade runs again at the next start.");
        return upgrade.Recorded;
    }

    private void Log(Exception ex)
    {
        // BUG-657: a fault a retry won't clear (a query the database can't run, a refused change) left the check lenient
        // for good with only a warning. It's an error now; the upgrade-path test's strict check catches it before release.
        if (IsDefect(ex))
            logger.LogError(ex, "The integrity upgrade failed with an error that won't clear on its own; the record check stays as before until it's fixed. Report it.");
        else
            logger.LogWarning(ex, "The integrity upgrade didn't finish; the record check stays as before and the upgrade runs again at the next start.");
    }

    /// <summary>
    /// BUG-657: whether a start-up fill or the upgrade failed for a reason a later start won't clear (a defect: a query EF
    /// can't translate, a refused change), rather than a database that timed out, was locked or lost a race.
    /// </summary>
    /// EF on SQL Server wraps a transient fault (a timeout, a dropped connection) in an InvalidOperationException whose
    /// inner exception is the real one, so that wrapper is judged by what it wraps (BUG-660 follow-up).
    public static bool IsDefect(Exception ex) =>
        ex is InvalidOperationException { InnerException: { } inner } && !Transient(ex) ? IsDefect(inner) : !Transient(ex);

    private static bool Transient(Exception ex) =>
        ex is Microsoft.EntityFrameworkCore.DbUpdateException or System.Data.Common.DbException or TimeoutException
            or ConcurrentEditException;
}
