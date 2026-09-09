using FluentAssertions;
using IncidentManager.Application.Dashboards;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

public class MetricsCsvTests
{
    private static readonly DateTimeOffset At = new(2026, 8, 10, 14, 30, 0, TimeSpan.Zero);

    private static DashboardMetrics Sample() => new(
        OpenCount: 5, Breaches: 2, Incidents: 2, AdverseEvents: 1,
        InternalOrigin: 3, ThirdPartyOrigin: 2, LegalReferred: 2, OverdueActionItems: 1,
        SlaAtRisk: 1, SlaBreached: 2,
        MeanHoursToContain: 4.5, MeanHoursToResolve: null,
        ByPhase: new[] { new PhaseCount(CasePhase.Triage, 3), new PhaseCount(CasePhase.Containment, 2) },
        Trend: new[]
        {
            new TrendPoint(2026, 1, 2, 1, 3),
            new TrendPoint(2026, 2, 1, 0, 4),
            new TrendPoint(2026, 3, 0, 2, 2),
        });

    [Fact]
    public void Header_and_core_metrics_are_emitted()
    {
        var csv = MetricsCsv.Build(Sample(), At);
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        lines[0].Should().Be("Metric,Value");
        csv.Should().Contain("Open items,5");
        csv.Should().Contain("Breaches,2");
        csv.Should().Contain("Legal-referred,2");
        csv.Should().Contain("Generated (UTC),2026-08-10 14:30:00");
    }

    [Fact]
    public void A_null_mean_is_written_as_an_empty_value()
    {
        var csv = MetricsCsv.Build(Sample(), At);
        csv.Should().Contain("Mean hours to contain,4.5");
        csv.Should().Contain("Mean hours to resolve,\r\n");
    }

    [Fact]
    public void Every_phase_is_listed_with_zero_for_phases_without_open_items()
    {
        var csv = MetricsCsv.Build(Sample(), At);
        // Triage has 3 open; New has none, so must appear as 0.
        csv.Should().Contain("Open in phase: Triage,3");
        csv.Should().Contain("Open in phase: New,0");
        foreach (var phase in Enum.GetValues<CasePhase>())
            csv.Should().Contain($"Open in phase: {phase}");
    }

    [Fact]
    public void Monthly_and_quarterly_trend_sections_are_emitted()
    {
        var csv = MetricsCsv.Build(Sample(), At);

        csv.Should().Contain("Month,Opened,Closed,Open at month end");
        csv.Should().Contain("2026-01,2,1,3");
        csv.Should().Contain("2026-03,0,2,2");

        // Q1 rollup: opened 2+1+0=3, closed 1+0+2=3, open at end = last month's value (2).
        csv.Should().Contain("Quarter,Opened,Closed,Open at quarter end");
        csv.Should().Contain("2026-Q1,3,3,2");
    }
}
