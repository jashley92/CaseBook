using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using IncidentManager.Application.Ops;
using IncidentManager.Web.Ops;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace IncidentManager.Web.HealthChecks;

/// <summary>
/// CAP-18: the alarms the app raises only in banners and the SIEM, rolled up into one word for a monitoring tool:
/// Healthy, or Degraded when any of them is up. The sources are the audit-chain verdict (<see cref="IIntegrityMonitor"/>),
/// evidence drift and store-wide evidence conditions (<see cref="IEvidenceIntegrityMonitor"/>), an evidence key that can't
/// be opened, a seal copy whose last attempt failed (<see cref="SealCopyStatus"/>) and a stale or missing backup
/// (<see cref="BackupHealthReader"/>). Tagged "alarms" only, never "ready": an alarm is for a person to look at, and
/// pulling the node out of the load balancer wouldn't fix any of them. The reasons go in the result's description,
/// which the endpoint's default writer never sends; the anonymous caller gets the status word only.
/// CAP-18 review (C10): the backup file is read once for every probe that asks while it's being read, and its answer kept
/// for <see cref="BackupKeepFor"/> (<paramref name="backupRead"/>, one per app), so an anonymous flood of requests on a
/// share that doesn't answer parks one thread, not one each.
/// </summary>
public sealed class AlarmsHealthCheck(
    IIntegrityMonitor integrity,
    IEvidenceIntegrityMonitor evidence,
    IEvidenceKeyring evidenceKeys,
    SealCopyStatus sealCopies,
    BackupHealthReader backup,
    SharedRead<BackupHealthReport>? backupRead = null) : IHealthCheck
{
    /// <summary>The check's registration tag; the readiness probe's predicate never selects it.</summary>
    public const string Tag = "alarms";

    /// <summary>How long a backup report is kept before the file is read again (the backup job writes it daily).</summary>
    public static readonly TimeSpan BackupKeepFor = TimeSpan.FromSeconds(30);

    private readonly SharedRead<BackupHealthReport> _backupRead = backupRead ?? new SharedRead<BackupHealthReport>(BackupKeepFor);

    /// <summary>How long the backup status file may take to read (C10: it may sit on a share that doesn't answer).</summary>
    public TimeSpan TimeLimit { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>How the backup report is read (replaceable in tests, to stand in for a share that doesn't answer).</summary>
    public Func<BackupHealthReport>? ReadBackup { get; init; }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var raised = new List<string>();
        try
        {
            if (integrity.Current is { IsValid: false }) raised.Add("audit chain broken");
            if (evidence.Current is { IsClean: false }) raised.Add("evidence drift");
            if (evidenceKeys.State == EvidenceKeyState.Unavailable) raised.Add("evidence key unavailable");
            if (sealCopies.Snapshot().Any(c => !c.Ok)) raised.Add("seal copy failing");

            var read = ReadBackup ?? backup.Read;
            var report = await _backupRead.Get(read).WaitAsync(TimeLimit, cancellationToken);
            // Not configured is a choice (development, or backups watched elsewhere), not an alarm.
            if (report.Overall is BackupHealthState.Stale or BackupHealthState.Missing or BackupHealthState.Failed) raised.Add("backup " + report.Overall.ToString().ToLowerInvariant());
        }
        catch (TimeoutException)
        {
            raised.Add($"backup status didn't answer within {TimeLimit.TotalSeconds:0} seconds");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            raised.Add("alarm check failed: " + ex.GetType().Name);
        }

        return raised.Count == 0 ? HealthCheckResult.Healthy() : HealthCheckResult.Degraded(string.Join("; ", raised));
    }
}
