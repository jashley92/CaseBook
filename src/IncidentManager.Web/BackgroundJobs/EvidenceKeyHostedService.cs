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
    IEvidenceIntegrityMonitor monitor, IEvidenceIntegrityAlertNotifier alerts, ILogger<EvidenceKeyHostedService> logger) : BackgroundService
{
    /// <summary>As the integrity upgrade's: longer than Upgrade-CaseBook.ps1's warm-up, so a failed upgrade rolls back first.</summary>
    public static readonly TimeSpan StartDelay = TimeSpan.FromMinutes(15);

    private static readonly TimeSpan Tick = TimeSpan.FromMinutes(1);
    private const int Batch = 200;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var started = DateTimeOffset.UtcNow;
        var lastLoad = DateTimeOffset.UtcNow;   // Program.cs loaded it at start-up
        DateTimeOffset? lastConversion = null;
        await ReportAsync(stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await Task.Delay(Tick, stoppingToken); }
            catch (OperationCanceledException) { return; }
            try
            {
                var now = DateTimeOffset.UtcNow;
                var every = keyring.State is EvidenceKeyState.Ready or EvidenceKeyState.Off ? TimeSpan.FromDays(1) : TimeSpan.FromMinutes(5);
                if (now - lastLoad >= every)
                {
                    await keyring.LoadAsync(stoppingToken);
                    lastLoad = now;
                    await ReportAsync(stoppingToken);
                }
                var due = status.NowRequested
                          || (now - started >= StartDelay && (lastConversion is null || status.Remaining > 0 || now - lastConversion >= TimeSpan.FromDays(1)));
                if (keyring.State == EvidenceKeyState.Ready && due)
                {
                    status.NowRequested = false;
                    while (await conversion.RunAsync(Batch, stoppingToken) > 0 && !stoppingToken.IsCancellationRequested) { }
                    lastConversion = now;
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception ex)
            {
                status.LastProblem = ex.Message;
                logger.LogError(ex, "The evidence key or file conversion check failed; it will try again in a minute.");
            }
        }
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
