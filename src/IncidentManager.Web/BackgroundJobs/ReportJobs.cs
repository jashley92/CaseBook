using System.Collections.Concurrent;
using System.Security.Claims;
using System.Threading.Channels;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.AspNetCore.Components.Authorization;

namespace IncidentManager.Web.BackgroundJobs;

public enum ReportJobState { Queued, Running, Done, Failed }

/// <summary>One report being generated in the background, as the Paper view and the toast show it.</summary>
public sealed record ReportJob(
    Guid Id, Guid CaseId, ReportKind Kind, string UserId, ReportJobState State, string? Stage,
    DateTimeOffset QueuedAtUtc, Guid? ReportId = null, string? FileName = null, string? Error = null)
{
    public bool IsActive => State is ReportJobState.Queued or ReportJobState.Running;
}

/// <summary>What to generate, and who asked (the run is theirs: attributed to them, with their permissions).</summary>
public sealed record ReportJobRequest(
    ClaimsPrincipal User, string UserId, Guid CaseId, ReportKind Kind, TlpLevel? Tlp, Guid? Template);

/// <summary>
/// RD-23: generates case and lessons-learned reports in the background, so the person who asked can keep working (or
/// leave the case) while it runs. A person's request is the act: the run happens in its own scope with their identity,
/// so the report, its audit lines and the permission and need-to-know checks are theirs, exactly as when it ran on the
/// page. Nothing is generated that nobody asked for. Jobs run one at a time in the order asked; progress and the result
/// are kept in memory for an hour (the stored report is the record). Process-local, like live updates.
/// </summary>
public sealed class ReportJobs : BackgroundService
{
    private static readonly TimeSpan Keep = TimeSpan.FromHours(1);

    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<ReportJobs> _logger;
    private readonly Func<IServiceProvider, ReportJobRequest, IProgress<string>, CancellationToken, Task<Report>> _generate;
    private readonly Channel<(Guid JobId, ReportJobRequest Request)> _queue = Channel.CreateUnbounded<(Guid, ReportJobRequest)>();
    private readonly ConcurrentDictionary<Guid, ReportJob> _jobs = new();

    public ReportJobs(IServiceScopeFactory scopes, ILogger<ReportJobs> logger)
        : this(scopes, logger, DefaultGenerate) { }

    /// <summary>For tests: the generation itself is swappable.</summary>
    public ReportJobs(IServiceScopeFactory scopes, ILogger<ReportJobs> logger,
        Func<IServiceProvider, ReportJobRequest, IProgress<string>, CancellationToken, Task<Report>> generate)
    {
        _scopes = scopes;
        _logger = logger;
        _generate = generate;
    }

    /// <summary>Raised on every change to a job (queued, a new stage, done, failed). Handlers must be quick.</summary>
    public event Action<ReportJob>? Changed;

    /// <summary>
    /// Asks for a report. If the same person already has one of that kind queued or running for the case, that job is
    /// returned instead of starting a second.
    /// </summary>
    public ReportJob Enqueue(ReportJobRequest request)
    {
        var running = _jobs.Values.FirstOrDefault(j => j.IsActive && j.CaseId == request.CaseId && j.Kind == request.Kind
                                                       && j.UserId == request.UserId);
        if (running is not null) return running;
        Prune();
        var job = new ReportJob(Guid.NewGuid(), request.CaseId, request.Kind, request.UserId, ReportJobState.Queued, null, DateTimeOffset.UtcNow);
        _jobs[job.Id] = job;
        _queue.Writer.TryWrite((job.Id, request));
        Raise(job);
        return job;
    }

    /// <summary>A person's jobs on a case, newest first.</summary>
    public IReadOnlyList<ReportJob> For(Guid caseId, string userId, ReportKind kind) =>
        _jobs.Values.Where(j => j.CaseId == caseId && j.UserId == userId && j.Kind == kind)
            .OrderByDescending(j => j.QueuedAtUtc).ToList();

    /// <summary>How many jobs are ahead of this one.</summary>
    public int Ahead(ReportJob job) =>
        _jobs.Values.Count(j => j.IsActive && j.Id != job.Id && j.QueuedAtUtc <= job.QueuedAtUtc);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var (id, request) in _queue.Reader.ReadAllAsync(stoppingToken))
                await RunAsync(id, request, stoppingToken);
        }
        catch (OperationCanceledException) { /* shutting down */ }
    }

    private async Task RunAsync(Guid id, ReportJobRequest request, CancellationToken ct)
    {
        Update(id, j => j with { State = ReportJobState.Running });
        try
        {
            await using var scope = _scopes.CreateAsyncScope();
            // The run is the requester's: their principal for this scope, so CurrentUser, permissions, need-to-know and
            // the audit trail all see them.
            if (scope.ServiceProvider.GetService<AuthenticationStateProvider>() is IHostEnvironmentAuthenticationStateProvider host)
                host.SetAuthenticationState(Task.FromResult(new AuthenticationState(request.User)));
            var progress = new SyncProgress(stage => Update(id, j => j with { Stage = stage }));
            var report = await _generate(scope.ServiceProvider, request, progress, ct);
            Update(id, j => j with { State = ReportJobState.Done, ReportId = report.Id, FileName = report.FileName });
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            if (ex is not (ArgumentException or InvalidOperationException or Application.Security.ForbiddenException))
                _logger.LogError(ex, "Report generation failed for case {CaseId}", request.CaseId);
            var message = ex is ArgumentException or InvalidOperationException or Application.Security.ForbiddenException
                ? ex.Message : "Something went wrong generating the report. Try again; if it keeps failing, tell an administrator.";
            Update(id, j => j with { State = ReportJobState.Failed, Error = message });
        }
    }

    private static Task<Report> DefaultGenerate(IServiceProvider sp, ReportJobRequest r, IProgress<string> progress, CancellationToken ct)
    {
        var reports = sp.GetRequiredService<ReportService>();
        return r.Kind == ReportKind.LessonsLearned
            ? reports.GenerateLessonsAsync(r.CaseId, r.Tlp, ct, r.Template, progress)
            : reports.GenerateAsync(r.CaseId, r.Tlp, ct, r.Template, progress);
    }

    private void Update(Guid id, Func<ReportJob, ReportJob> change)
    {
        if (!_jobs.TryGetValue(id, out var job)) return;
        var next = change(job);
        _jobs[id] = next;
        Raise(next);
    }

    private void Raise(ReportJob job)
    {
        try { Changed?.Invoke(job); }
        catch (Exception ex) { _logger.LogDebug(ex, "A report job listener failed"); }
    }

    private void Prune()
    {
        var cutoff = DateTimeOffset.UtcNow - Keep;
        foreach (var j in _jobs.Values.Where(j => !j.IsActive && j.QueuedAtUtc < cutoff).ToList()) _jobs.TryRemove(j.Id, out _);
    }

    // Progress<T> posts to a captured context; this reports on the worker's own thread.
    private sealed class SyncProgress(Action<string> report) : IProgress<string>
    {
        public void Report(string value) => report(value);
    }
}
