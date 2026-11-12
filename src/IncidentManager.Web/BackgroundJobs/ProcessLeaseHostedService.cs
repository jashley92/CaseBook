using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Persistence;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// Keeps the background jobs' lease (<see cref="IProcessLease"/>). It takes the lease before the jobs start, renews it
/// every <see cref="DbProcessLease.RenewEvery"/> and lets it go at shutdown. Registered before every job, so it starts
/// first and stops last. A process that doesn't hold the lease stands by, and the jobs skip their passes there
/// (<see cref="IJobStatus.TryStart"/> refuses them).
/// </summary>
public sealed class ProcessLeaseHostedService(IProcessLease lease, ILogger<ProcessLeaseHostedService> logger, TimeProvider? time = null)
    : BackgroundService
{
    /// <summary>How long start-up waits for the first take before the jobs start without it (they then wait for it).</summary>
    public static readonly TimeSpan FirstTakeLimit = TimeSpan.FromSeconds(15);

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        // The first take is awaited, so each job's first pass finds the lease already decided rather than skipping.
        try { await lease.HoldAsync(cancellationToken).WaitAsync(FirstTakeLimit, cancellationToken); }
        catch (TimeoutException) { logger.LogWarning("The background jobs' lease wasn't decided within {Seconds} s of start-up; the jobs wait for it.", FirstTakeLimit.TotalSeconds); }
        await base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var clock = time ?? TimeProvider.System;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(DbProcessLease.RenewEvery, clock, stoppingToken);
                await lease.HoldAsync(stoppingToken);   // never throws but to cancel
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);
        // Never fails the shutdown: a lease not let go lapses within its expiry.
        try { await lease.ReleaseAsync(cancellationToken); }
        catch (Exception ex) when (ex is ObjectDisposedException or OperationCanceledException or AggregateException)
        {
            // Not logged: the loggers may be gone too. A lease not let go lapses on its own.
        }
    }
}
