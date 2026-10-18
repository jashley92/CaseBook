using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// PROD-57: keeps the evidence key and the files it protects in order.
/// <list type="bullet">
/// <item>The key is checked again every 5 minutes while it isn't ready (a certificate restored, CyberArk back, a backup
/// added: no restart needed), and once a day when it is: every envelope copy, the recovery certificates, renewals.</item>
/// <item>While it's unavailable, the evidence integrity monitor carries one "evidence key unavailable" finding: the
/// administrators' banner and the integrity alert email, once per episode; it clears when the key is back.</item>
/// <item>Once the key is ready, files stored before (or restored from an older backup) are encrypted in batches, starting
/// <see cref="StartDelay"/> after start-up so the upgrade script's warm-up and rollback come first; then daily, and at
/// once when an administrator presses Convert now.</item>
/// </list>
/// </summary>
public sealed class EvidenceKeyHostedService(EvidenceKeyring keyring, EvidenceConversion conversion, EvidenceConversionStatus status,
    IEvidenceIntegrityMonitor monitor, IEvidenceIntegrityAlertNotifier alerts, ILogger<EvidenceKeyHostedService> logger,
    IJobStatus? jobs = null) : BackgroundService
{
    /// <summary>
    /// CAP-29: this job's row on Diagnostics: a run is a pass that re-read the key or converted files (its items); Convert
    /// now is on the Evidence encryption card, so no Run now here.
    /// </summary>
    public static readonly JobDefinition Job = new("evidence-key", "Evidence key and file conversion",
        "key every 5 minutes until ready, then daily; conversion daily, or Convert now");

    /// <summary>As the integrity upgrade's: longer than Upgrade-CaseBook.ps1's warm-up, so a failed upgrade rolls back first.</summary>
    public static readonly TimeSpan StartDelay = TimeSpan.FromMinutes(15);

    private static readonly TimeSpan Tick = TimeSpan.FromMinutes(1);
    private const int Batch = 200;

    /// <summary>How long files left over wait after a run that converted none of them.</summary>
    public static readonly TimeSpan RetryIdle = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var started = DateTimeOffset.UtcNow;
        var lastLoad = DateTimeOffset.UtcNow;   // Program.cs loaded it at start-up
        var envelopeStamp = EnvelopeStamp();
        DateTimeOffset? lastConversion = null;
        var lastRunConverted = false;
        jobs?.Register(Job);
        await ReportAsync(stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await Task.Delay(Tick, stoppingToken); }
            catch (OperationCanceledException) { return; }
            JobRun? run = null;   // CAP-29: begun only when this tick does something
            try
            {
                var now = DateTimeOffset.UtcNow;
                var every = keyring.State is EvidenceKeyState.Ready or EvidenceKeyState.Off ? TimeSpan.FromDays(1) : TimeSpan.FromMinutes(5);
                // PROD-59: casebook-keytool changed the keys folder's envelope (shares issued, a drill, a recovery, an export):
                // read it now, so what it did reaches the audit trail and the SIEM within a minute, not at the daily check.
                var stamp = EnvelopeStamp();
                var touched = stamp != envelopeStamp;
                envelopeStamp = stamp;
                if (now - lastLoad >= every || touched)
                {
                    run ??= jobs.Begin(Job);
                    await keyring.LoadAsync(stoppingToken);
                    lastLoad = now;
                    await ReportAsync(stoppingToken);
                }
                // Review finding 9: files left over (in use, no room) are tried again at once while runs are converting, but
                // after a run that converted nothing only hourly, so a store that can't make progress isn't re-listed and
                // re-opened every minute (holding the gate the evidence re-check shares).
                var retry = lastRunConverted ? TimeSpan.Zero : RetryIdle;
                var due = status.NowRequested
                          || (now - started >= StartDelay && (lastConversion is null
                                                              || (status.Remaining > 0 && now - lastConversion >= retry)
                                                              || now - lastConversion >= TimeSpan.FromDays(1)));
                long? convertedItems = null;
                if (keyring.State == EvidenceKeyState.Ready && due)
                {
                    run ??= jobs.Begin(Job);
                    status.NowRequested = false;
                    var converted = 0;
                    int batch;
                    while ((batch = await conversion.RunAsync(Batch, stoppingToken)) > 0 && !stoppingToken.IsCancellationRequested) converted += batch;
                    lastConversion = now;
                    lastRunConverted = converted > 0;
                    convertedItems = converted;
                }
                if (keyring.State == EvidenceKeyState.Unavailable) run?.Failed("Evidence key unavailable");   // why: its card
                else run?.Succeeded(convertedItems);
                jobs?.Scheduled(Job, keyring.State != EvidenceKeyState.Off, lastLoad + every);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { run?.Dispose(); return; }
            catch (Exception ex)
            {
                run?.Failed(ex);
                status.LastProblem = ex.Message;
                logger.LogError(ex, "The evidence key or file conversion check failed; it will try again in a minute.");
            }
            run?.Dispose();
        }
    }

    // The keys folder's envelope's last write (local data root, so cheap); null when it isn't there or can't be read.
    private DateTime? EnvelopeStamp()
    {
        try { return File.Exists(keyring.EnvelopePath) ? File.GetLastWriteTimeUtc(keyring.EnvelopePath) : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    // The key's state on the evidence monitor: one finding while it's unavailable, alarmed once.
    private async Task ReportAsync(CancellationToken ct)
    {
        var problem = keyring.State == EvidenceKeyState.Unavailable ? keyring.Problem ?? "The evidence key can't be opened." : null;
        if (!monitor.RecordCondition(EvidenceDriftKind.KeyUnavailable, problem, DateTimeOffset.UtcNow) || problem is null) return;
        var drift = new EvidenceDrift(Guid.Empty, Guid.Empty, null, "(the evidence key)", "", null, EvidenceDriftKind.KeyUnavailable, problem);
        await alerts.OnDriftDetectedAsync(new EvidenceVerificationResult(0, [drift], DateTimeOffset.UtcNow, new HashSet<Guid>(), new HashSet<Guid>()), ct);
    }
}
