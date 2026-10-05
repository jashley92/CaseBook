using System.Security.Claims;
using FluentAssertions;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.BackgroundJobs;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// RD-23: background report generation. A job runs in its own scope as the person who asked (so the report and its audit
/// lines are theirs), reports its stages, isn't started twice for the same case and kind, and says why when it fails.
/// </summary>
public sealed class ReportJobsTests
{
    private static ServiceProvider Services() => new ServiceCollection()
        .AddScoped<AuthenticationStateProvider, ServerAuthenticationStateProvider>()
        .BuildServiceProvider();

    private static ReportJobRequest Request(Guid caseId, ReportKind kind = ReportKind.Case) => new(
        new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "robin")], "test")),
        "robin", caseId, kind, TlpLevel.Amber, null);

    private static async Task<ReportJob> Until(ReportJobs jobs, Guid caseId, ReportKind kind, Func<ReportJob, bool> done)
    {
        for (var i = 0; i < 200; i++)
        {
            if (jobs.For(caseId, "robin", kind).FirstOrDefault() is { } j && done(j)) return j;
            await Task.Delay(20);
        }
        throw new TimeoutException();
    }

    [Fact]
    public async Task A_job_runs_as_the_requester_reports_its_stages_and_is_not_started_twice()
    {
        using var sp = Services();
        var release = new TaskCompletionSource();
        string? ranAs = null;
        var stages = new List<string>();
        var jobs = new ReportJobs(sp.GetRequiredService<IServiceScopeFactory>(), NullLogger<ReportJobs>.Instance,
            async (scope, r, progress, ct) =>
            {
                ranAs = (await scope.GetRequiredService<AuthenticationStateProvider>().GetAuthenticationStateAsync())
                    .User.FindFirstValue(ClaimTypes.NameIdentifier);
                progress.Report(ReportStages.Reading);
                await release.Task;
                progress.Report(ReportStages.Storing);
                return new Report { FileName = "2026-01_Report_v1.docx" };
            });
        jobs.Changed += j => { if (j.Stage is { } s && !stages.Contains(s)) stages.Add(s); };
        await jobs.StartAsync(CancellationToken.None);

        var caseId = Guid.NewGuid();
        var first = jobs.Enqueue(Request(caseId));
        await Until(jobs, caseId, ReportKind.Case, j => j.Stage == ReportStages.Reading);
        jobs.Enqueue(Request(caseId)).Id.Should().Be(first.Id);   // already running: no second job

        release.SetResult();
        var done = await Until(jobs, caseId, ReportKind.Case, j => j.State == ReportJobState.Done);
        done.FileName.Should().Be("2026-01_Report_v1.docx");
        ranAs.Should().Be("robin");
        stages.Should().Equal(ReportStages.Reading, ReportStages.Storing);

        await jobs.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task A_failed_job_says_why()
    {
        using var sp = Services();
        var jobs = new ReportJobs(sp.GetRequiredService<IServiceScopeFactory>(), NullLogger<ReportJobs>.Instance,
            (_, _, _, _) => throw new InvalidOperationException("Case not found."));
        await jobs.StartAsync(CancellationToken.None);
        var caseId = Guid.NewGuid();
        jobs.Enqueue(Request(caseId, ReportKind.LessonsLearned));
        var failed = await Until(jobs, caseId, ReportKind.LessonsLearned, j => j.State == ReportJobState.Failed);
        failed.Error.Should().Be("Case not found.");
        await jobs.StopAsync(CancellationToken.None);
    }
}
