using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Evidence;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>PROD-56: the evidence store's last probe, for Diagnostics (in memory since start-up).</summary>
public sealed class EvidenceStoreStatus
{
    public DateTimeOffset? CheckedAtUtc { get; private set; }

    /// <summary>Null when the store could be written and read at the last probe, else why not.</summary>
    public string? Problem { get; private set; }

    internal void Record(DateTimeOffset at, string? problem) => (CheckedAtUtc, Problem) = (at, problem);
}

/// <summary>
/// PROD-56: at start-up, deletes parts left by large uploads that a restart cut off (none can be in progress yet: they're
/// held in memory), then checks the store can be written and read as the app's account, which matters most for a store
/// on a network share. Every hour after, it drops abandoned uploads and probes again. A failed probe is logged once per
/// change, with the store and the reason.
/// </summary>
public sealed class EvidenceStoreHostedService(IEvidenceStore store, EvidenceUploadSessions uploads, EvidenceStoreStatus status,
    IClock clock, ILogger<EvidenceStoreHostedService> logger) : BackgroundService
{
    private static readonly TimeSpan Every = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var first = true;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (first)
                {
                    // PROD-59: uploads cut off by the restart are put back (resumable) before the sweep, which keeps them.
                    var restored = await EvidenceService.RestoreUploadsAsync(uploads, store, stoppingToken);
                    if (restored > 0) logger.LogInformation("Kept {Count} unfinished large upload(s) to resume.", restored);
                }
                var removed = await EvidenceService.SweepUploadsAsync(uploads, store, clock.UtcNow,
                    first ? TimeSpan.Zero : EvidenceUploadSessions.IdleLimit, stoppingToken);
                if (removed > 0) logger.LogInformation("Removed {Count} abandoned large upload(s) from the evidence store.", removed);
                await ProbeAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception ex)
            {
                logger.LogError(ex, "The evidence store's upkeep failed; it will try again in an hour.");
            }
            first = false;
            try { await Task.Delay(Every, stoppingToken); }
            catch (OperationCanceledException) { return; }
        }
    }

    private async Task ProbeAsync(CancellationToken ct)
    {
        var before = status.Problem;
        var problem = await store.ProbeAsync(ct);
        status.Record(clock.UtcNow, problem);
        if (problem is not null && problem != before)
            logger.LogError("The evidence store at {Location} can't be written and read as {Account}: {Problem}. Uploads and downloads " +
                            "will fail until it's fixed (check the folder and share permissions).", store.Location,
                Environment.UserDomainName + "\\" + Environment.UserName, problem);
        else if (problem is null && before is not null)
            logger.LogInformation("The evidence store at {Location} can be written and read again.", store.Location);
    }
}
