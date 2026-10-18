using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// CAP-29: Diagnostics' Run now (scoped: it acts as the signed-in administrator). Only a job registered as a read-only scan
/// with a pass of its own can be run (ADR 0004: nothing a person starts here writes case data); <c>Administer</c> is checked
/// here, not only by the page. The run takes the job's slot in <see cref="IJobStatus"/>, so it's refused while the job runs
/// (scheduled or another Run now), and a scheduled pass that comes due meanwhile is skipped until the next poll. It runs in
/// the background until it finishes or the app stops; the table shows its outcome. Each start is in the audit trail.
/// </summary>
public sealed class JobRunNowService(
    IJobStatus jobs,
    ICurrentUser user,
    IAuditWriter audit,
    IHostApplicationLifetime lifetime,
    ILogger<JobRunNowService> logger,
    ISecurityEventSink? siem = null)
{
    /// <summary>The audit trail's entity type for a Run now.</summary>
    public const string AuditEntity = "ScheduledJob";

    /// <summary>Whether <paramref name="job"/> may be run from Diagnostics (a read-only scan with a pass registered).</summary>
    public bool CanRunNow(JobDefinition job) => job.RunNow && jobs.RunNowPass(job.Key) is not null;

    /// <summary>
    /// Starts <paramref name="key"/>'s pass now, in the background, and returns the task it runs as (the page doesn't wait
    /// for it). Refused, with words, when the job isn't a read-only scan or is running.
    /// </summary>
    public async Task<Task> RunNowAsync(string key, CancellationToken ct = default)
    {
        Require();
        var job = jobs.Snapshot().Select(r => r.Job).FirstOrDefault(j => string.Equals(j.Key, key, StringComparison.Ordinal))
                  ?? throw new InvalidOperationException("That job isn't running in this app.");
        var pass = job.RunNow ? jobs.RunNowPass(job.Key) : null;
        if (pass is null)
            throw new InvalidOperationException($"{job.Name} can't be run from here: only the read-only scans can.");
        var run = jobs.TryStart(job, manual: true)
                  ?? throw new InvalidOperationException($"{job.Name} is running now. Wait for it to finish, then try again.");
        try
        {
            await audit.RecordAsync(AuditAction.Access, AuditEntity, job.Key, null, $"{job.Name} run now from Diagnostics.", ct);
        }
        catch
        {
            run.Dispose();   // not recorded, so not run
            throw;
        }
        var stopping = lifetime.ApplicationStopping;
        return Task.Run(async () =>
        {
            try { await pass(run, stopping); }
            catch (Exception ex) when (ex is not OperationCanceledException || !stopping.IsCancellationRequested)
            {
                run.Failed(ex);
                logger.LogError(ex, "{Job} (run from Diagnostics) failed.", job.Name);
            }
            finally { run.Dispose(); }
        }, CancellationToken.None);
    }

    // As AdminActionPermissions.Require does for the Application services: Administer, a refusal streamed to the SIEM.
    private void Require([System.Runtime.CompilerServices.CallerMemberName] string action = "")
    {
        if (user.Has(Permission.Administer)) return;
        var key = $"{nameof(JobRunNowService)}.{action}";
        siem?.Emit(SecurityEvents.ActionRefused(user.UserId, user.UserPrincipalName, Permission.Administer, key));
        throw new ForbiddenException(Permission.Administer, key);
    }
}
