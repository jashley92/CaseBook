using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>BUG-555: going back to unreported on an impact update keeps what was in play when the case was reported.</summary>
public class CaseUnreportTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);

    private static Case Reported(IReadOnlyCollection<string> inPlay)
    {
        var c = Case.Open(2026, 1, "Breach", "Breach case", Classification.Breach, Severity.High,
            CaseOrigin.InternalDetection, "alice", Now.AddHours(-5));
        c.SetImpactAssessment(10, ["EMAIL"], null, "alice", Now);
        c.MarkReported(Now.AddHours(-1), "alice", Now, inPlay);
        return c;
    }

    [Fact]
    public void Unreport_clears_the_reported_time_and_keeps_the_kept_set()
    {
        var c = Reported([]);
        c.ReportedJurisdictions.Should().Be(";EMAIL");

        c.Unreport(["EMAIL"], "bob", Now);

        c.ReportedAtUtc.Should().BeNull();
        c.ReportedJurisdictions.Should().Be(";EMAIL");
    }

    [Fact]
    public void A_kept_set_from_before_its_elements_were_recorded_gets_the_elements_before_the_edit()
    {
        var c = Reported([]);
        c.ReportedJurisdictions = "";   // back-filled at start-up, without the elements

        c.Unreport(["EMAIL", "email"], "bob", Now);

        c.ReportedJurisdictions.Should().Be(";EMAIL");
        Case.KeptInPlay(c.ReportedJurisdictions, ["EMAIL", "DL"], added => added.Contains("DL") ? ["NJ"] : [])
            .Should().Equal("NJ");
    }

    [Fact]
    public void A_legacy_kept_set_gets_the_elements_before_they_change(/* BUG-563 */)
    {
        var c = Reported(["NY"]);
        c.ReportedJurisdictions = "NY";   // back-filled before the elements were recorded

        c.SetImpactAssessment(20, ["EMAIL"], null, "bob", Now);   // the count only: nothing to tell apart
        c.ReportedJurisdictions.Should().Be("NY");

        c.SetImpactAssessment(20, ["EMAIL", "DL"], null, "bob", Now);
        c.ReportedJurisdictions.Should().Be("NY;EMAIL");
        // Every reader now sees DL as added, with or without the elements before the edit.
        Case.KeptInPlay(c.ReportedJurisdictions, ["EMAIL", "DL"], added => added.Contains("DL") ? ["NJ"] : [])
            .Should().Equal("NY", "NJ");

        c.SetImpactAssessment(20, ["DL"], null, "bob", Now);   // a later edit keeps what was recorded
        c.ReportedJurisdictions.Should().Be("NY;EMAIL");
    }

    [Fact]
    public void A_case_not_reported_is_left_alone()
    {
        var c = Reported([]);
        c.ClearReported("bob", Now);

        c.Unreport(["EMAIL"], "bob", Now);

        c.ReportedJurisdictions.Should().BeNull();
    }
}
