using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>INV-36: the case summary is the brief's first part, and every change to it is a brief version.</summary>
public class BriefSummaryTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 1, 8, 0, 0, TimeSpan.Zero);

    private static Case NewCase() => Case.Open(2026, 7, "Phish", "Credential phishing", Classification.Incident,
        Severity.High, CaseOrigin.InternalDetection, "ic1", T0);

    [Fact]
    public void The_intake_summary_is_version_one_and_a_blank_one_records_nothing()
    {
        var c = NewCase();
        c.SetInitialSummary("  Lure reached Finance.  ", "ic1", T0);

        c.Summary.Should().Be("Lure reached Finance.");
        c.Briefs.Should().ContainSingle().Which.Should().Match<CaseBrief>(b => b.Version == 1 && b.Summary == "Lure reached Finance.");

        var blank = NewCase();
        blank.SetInitialSummary("   ", "ic1", T0);
        blank.Summary.Should().BeNull();
        blank.Briefs.Should().BeEmpty();
    }

    [Fact]
    public void Revising_the_brief_sets_the_case_summary_and_keeps_the_earlier_one()
    {
        var c = NewCase();
        c.SetInitialSummary("Lure reached Finance.", "ic1", T0);
        c.ReviseBrief("One mailbox accessed.", "Opportunistic", null, null, null, "an1", T0.AddHours(1));

        c.Summary.Should().Be("One mailbox accessed.");
        c.Briefs.Single(b => !b.IsCurrent).Summary.Should().Be("Lure reached Finance.");
        c.Briefs.Single(b => b.IsCurrent).Version.Should().Be(2);
    }

    [Fact]
    public void A_summary_changed_in_the_details_is_a_new_version_carrying_the_other_parts()
    {
        var c = NewCase();
        c.ReviseBrief("First", "Assessment", "Known", "Open?", "Next", "an1", T0.AddHours(1));

        c.UpdateDetails("Credential phishing", "Second", null, null, null, T0, null, "an1", T0.AddHours(2));

        var current = c.Briefs.Single(b => b.IsCurrent);
        current.Should().Match<CaseBrief>(b => b.Version == 2 && b.Summary == "Second" && b.WorkingAssessment == "Assessment"
                                               && b.Known == "Known" && b.OpenQuestions == "Open?" && b.NextSteps == "Next");
        c.Summary.Should().Be("Second");
    }

    [Fact]
    public void Clearing_the_summary_in_the_details_is_recorded_and_an_unchanged_one_is_not()
    {
        var c = NewCase();
        c.SetInitialSummary("First", "ic1", T0);

        c.UpdateDetails("Renamed", "First", null, null, null, T0, null, "an1", T0.AddHours(1));
        c.Briefs.Should().HaveCount(1, "the summary didn't change");

        c.UpdateDetails("Renamed", null, null, null, null, T0, null, "an1", T0.AddHours(2));
        c.Summary.Should().BeNull();
        c.Briefs.Should().HaveCount(2);
        c.Briefs.Single(b => b.IsCurrent).IsEmpty.Should().BeTrue("clearing the summary is a version too");
    }
}
