using FluentAssertions;
using IncidentManager.Application.Dashboards;
using IncidentManager.Application.Mitre;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>E-31: the quarterly program-metrics report — figures by the date things happened, vs the prior quarter.</summary>
public sealed class ProgramReportTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 24, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "mgr", RoleSet = [AppRole.Manager] };

    // Q2 2026 = Apr–Jun; Q1 = Jan–Mar.
    private static readonly ProgramPeriod Q2 = new(2026, 2);
    private static DateTimeOffset Apr(int d, int h = 0) => new(2026, 4, d, h, 0, 0, TimeSpan.Zero);
    private static DateTimeOffset Feb(int d) => new(2026, 2, d, 0, 0, 0, TimeSpan.Zero);

    public ProgramReportTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private DbContextOptions<AppDbContext> Options() =>
        new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;

    private ProgramReportService Service(SlaTargets? targets = null)
    {
        var f = new TestDbContextFactory(Options());
        return new(f, _user, _clock, new TestSlaTargets(targets), new AttackCoverageService(f, _user, _clock));
    }

    private async Task SeedAsync()
    {
        await using var db = new AppDbContext(Options());
        await db.Database.EnsureCreatedAsync();

        // Q2: a High incident contained in 2h (met a 4h target), resolved in 30h, with a review + two actions.
        var a = Case.Open(2026, 1, "A", "Phish", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic", Apr(2));
        a.OccurredAtUtc = Apr(1, 18);
        a.ContainedAtUtc = Apr(2, 2);
        a.ResolvedAtUtc = Apr(3, 6);
        a.AddTechnique("T1566", "Phishing", MitreTactic.InitialAccess, "ic", Apr(2));
        // Q2: a Critical breach contained in 10h (missed a 4h target), reported, closed in Q2.
        var b = Case.Open(2026, 2, "B", "Exposure", Classification.Incident, Severity.Critical, CaseOrigin.ThirdParty, "ic", Apr(10));
        b.Reclassify(Classification.Breach, "PII in scope", "ic", Apr(11));
        b.ContainedAtUtc = Apr(10, 10);
        b.ReportedAtUtc = Apr(12);
        b.ClosedAtUtc = Apr(20);
        // Q1: one adverse event, closed in Q1.
        var c = Case.Open(2026, 3, "C", "Old", Classification.AdverseEvent, Severity.Low, CaseOrigin.InternalDetection, "ic", Feb(1));
        c.ClosedAtUtc = Feb(5);
        // A drill in Q2 — excluded by default.
        var drill = Case.Open(2026, 4, "D", "Tabletop", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic", Apr(5), isExercise: true);

        db.Cases.AddRange(a, b, c, drill);
        db.PostIncidentReviews.Add(new PostIncidentReview { CaseId = a.Id, WhatHappened = "x", CreatedAtUtc = Apr(15), CreatedBy = "ic" });
        db.ImprovementActions.AddRange(
            new ImprovementAction { CaseId = a.Id, Title = "MFA for finance", RelatedArea = "Identity", CreatedAtUtc = Apr(15), CreatedBy = "ic",
                Status = ImprovementActionStatus.Completed, ClosedAtUtc = Apr(25) },
            new ImprovementAction { CaseId = a.Id, Title = "Phish training", RelatedArea = "Awareness", CreatedAtUtc = Apr(15), CreatedBy = "ic",
                TargetDateUtc = Apr(20) });
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task A_quarter_counts_what_happened_in_it_and_compares_with_the_previous()
    {
        await SeedAsync();
        var targets = new SlaTargets(new Dictionary<(SlaClock, Severity), int>
        {
            [(SlaClock.Containment, Severity.High)] = 4,
            [(SlaClock.Containment, Severity.Critical)] = 4,
        }, 80);

        var r = await Service(targets).BuildAsync(Q2);
        var q2 = r.Current;

        q2.Opened.Should().Be(2, "the drill is excluded and C opened in Q1");
        q2.Closed.Should().Be(1);
        q2.OpenAtEnd.Should().Be(1);
        q2.OpenedByClassification.Should().Equal(new CountBy<Classification?>(Classification.Incident, 1),
            new CountBy<Classification?>(Classification.Breach, 1));
        q2.TimeToDetect.MedianHours.Should().Be(6);
        q2.TimeToContain.Should().Be(new Interval(6, 6, 2));   // 2h and 10h
        q2.Sla.Single(s => s.Clock == SlaClock.Containment).Should().Be(new SlaAttainment(SlaClock.Containment, 1, 1));
        q2.BreachesOpened.Should().Be(1);
        q2.ReportedToRegulators.Should().Be(1);
        q2.ReviewsRecorded.Should().Be(1);
        q2.ActionsOpened.Should().Be(2);
        q2.ActionsCompleted.Should().Be(1);
        q2.ActionsOpenAtEnd.Should().Be(1);
        q2.ActionsPastTargetAtEnd.Should().Be(1);
        q2.ActionAreas.Select(x => x.Key).Should().BeEquivalentTo("Identity", "Awareness");
        r.TopTechniques.Should().ContainSingle(t => t.TechniqueId == "T1566" && t.Cases == 1);

        r.Previous.Opened.Should().Be(1);
        r.Previous.Closed.Should().Be(1);
        r.Period.Previous.Label.Should().Be("Q1 2026");
    }

    [Fact]
    public async Task Exercises_join_only_when_asked_and_the_csv_carries_both_quarters()
    {
        await SeedAsync();

        var r = await Service().BuildAsync(Q2, includeExercises: true);
        r.Current.Opened.Should().Be(3);

        var csv = ProgramReportService.ToCsv(r, c => c?.ToString() ?? "Complex Event", s => s.ToString());
        csv.Should().Contain("section,metric,Q2 2026,Q1 2026");
        csv.Should().Contain("Volume,Cases opened,3,1");
        csv.Should().Contain("(includes exercise cases)");
    }

    [Fact]
    public void Quarters_are_calendar_quarters()
    {
        ProgramPeriod.Containing(new DateTimeOffset(2026, 9, 24, 0, 0, 0, TimeSpan.Zero)).Should().Be(new ProgramPeriod(2026, 3));
        new ProgramPeriod(2026, 1).Previous.Should().Be(new ProgramPeriod(2025, 4));
        new ProgramPeriod(2026, 4).End.Should().Be(new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero));
        ProgramPeriod.TryCreate(2026, 5).Should().BeNull();
    }

    public void Dispose() => _connection.Dispose();
}
