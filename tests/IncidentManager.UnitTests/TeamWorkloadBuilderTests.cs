using FluentAssertions;
using IncidentManager.Application.Sla;
using IncidentManager.Application.Work;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

public class TeamWorkloadBuilderTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 20, 12, 0, 0, TimeSpan.Zero);

    private static readonly SlaTargets Targets = new(
        new Dictionary<(SlaClock, Severity), int> { [(SlaClock.Containment, Severity.Critical)] = 4 }, 80);

    private static WorkloadWorker Ic(string id, string name) => new(id, name, true);
    private static WorkloadWorker Analyst(string id, string name) => new(id, name, false);

    private static WorkloadCaseRow Row(Severity sev, DateTimeOffset lastActivity,
        DateTimeOffset? detected = null, DateTimeOffset? contained = null, params WorkloadWorker[] workers)
        => new(sev, CasePhase.Triage, detected, contained, null, lastActivity, workers);

    [Fact]
    public void A_case_counts_toward_each_assigned_worker()
    {
        var rows = new[]
        {
            Row(Severity.High, Now, workers: new[] { Analyst("u1", "Alex"), Analyst("u2", "Blair") }),
        };

        var w = TeamWorkloadBuilder.Build(rows, Targets, Now);

        w.TotalOpen.Should().Be(1);            // one case…
        w.AnalystCount.Should().Be(2);          // …carried by two people
        w.Analysts.Should().OnlyContain(a => a.Open == 1 && a.High == 1);
        w.Unassigned.Open.Should().Be(0);
    }

    [Fact]
    public void A_case_with_no_workers_lands_in_the_unassigned_queue()
    {
        var rows = new[] { Row(Severity.Medium, Now) };

        var w = TeamWorkloadBuilder.Build(rows, Targets, Now);

        w.Analysts.Should().BeEmpty();
        w.Unassigned.Open.Should().Be(1);
        w.Unassigned.Medium.Should().Be(1);
    }

    [Fact]
    public void Ic_assignments_are_counted_separately()
    {
        var rows = new[]
        {
            Row(Severity.Critical, Now, workers: new[] { Ic("u1", "Ivy") }),
            Row(Severity.Low, Now, workers: new[] { Analyst("u1", "Ivy") }),
        };

        var w = TeamWorkloadBuilder.Build(rows, Targets, Now);

        var ivy = w.Analysts.Should().ContainSingle().Subject;
        ivy.Open.Should().Be(2);
        ivy.AsIncidentCommander.Should().Be(1);
        ivy.Critical.Should().Be(1);
        ivy.Low.Should().Be(1);
    }

    [Fact]
    public void Breached_sla_is_counted_per_worker()
    {
        var rows = new[]
        {
            // Critical, detected 10h ago, not contained → past the 4h containment target → breached.
            Row(Severity.Critical, Now, detected: Now.AddHours(-10), workers: new[] { Analyst("u1", "Alex") }),
            // Critical, detected now → on track (neither at-risk nor breached).
            Row(Severity.Critical, Now, detected: Now, workers: new[] { Analyst("u1", "Alex") }),
        };

        var alex = TeamWorkloadBuilder.Build(rows, Targets, Now).Analysts.Single();

        alex.Open.Should().Be(2);
        alex.SlaBreached.Should().Be(1);
        alex.SlaAtRisk.Should().Be(0);
    }

    [Fact]
    public void Stale_flags_cases_without_recent_activity()
    {
        var rows = new[]
        {
            Row(Severity.Low, Now.AddDays(-10), workers: new[] { Analyst("u1", "Alex") }), // stale (>7d)
            Row(Severity.Low, Now.AddDays(-2), workers: new[] { Analyst("u1", "Alex") }),  // fresh
        };

        var alex = TeamWorkloadBuilder.Build(rows, Targets, Now).Analysts.Single();

        alex.Stale.Should().Be(1);
    }

    [Fact]
    public void Analysts_are_ordered_by_heaviest_load_first()
    {
        var rows = new[]
        {
            Row(Severity.Low, Now, workers: new[] { Analyst("light", "Light") }),
            Row(Severity.Low, Now, workers: new[] { Analyst("heavy", "Heavy") }),
            Row(Severity.Low, Now, workers: new[] { Analyst("heavy", "Heavy") }),
        };

        var w = TeamWorkloadBuilder.Build(rows, Targets, Now);

        w.Analysts[0].DisplayName.Should().Be("Heavy");
        w.Analysts[0].Open.Should().Be(2);
        w.Analysts[1].DisplayName.Should().Be("Light");
    }
}
