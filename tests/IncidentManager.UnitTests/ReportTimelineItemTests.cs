using FluentAssertions;
using IncidentManager.Application.Reporting;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>INV-46: the built-in report's investigation timeline prints who recorded each row in "By", and an
/// entry's own source (the tool) after its text.</summary>
public class ReportTimelineItemTests
{
    private static readonly DateTimeOffset At = new(2026, 9, 25, 22, 0, 0, TimeSpan.Zero);

    [Fact]
    public void An_entry_source_follows_the_description()
    {
        new ReportTimelineItem(At, "Analysis", "Reviewed mailbox logs.", "SIEM", By: "Alex Analyst")
            .DescriptionWithSource.Should().Be("Reviewed mailbox logs. (Source: SIEM)");
    }

    [Fact]
    public void No_source_or_one_that_repeats_the_type_adds_nothing()
    {
        new ReportTimelineItem(At, "Analysis", "Reviewed.", null).DescriptionWithSource.Should().Be("Reviewed.");
        new ReportTimelineItem(At, "Handoff", "Handed to Bob.", "Handoff").DescriptionWithSource.Should().Be("Handed to Bob.");
    }

    [Fact]
    public void A_milestone_actor_is_not_repeated_as_a_source()
    {
        new ReportTimelineItem(At, ReportTimelineItem.Milestone, "Phase New → Containment", "Ivy Commander", By: "Ivy Commander")
            .DescriptionWithSource.Should().Be("Phase New → Containment");
    }
}
