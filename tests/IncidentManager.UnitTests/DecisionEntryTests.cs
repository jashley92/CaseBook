using FluentAssertions;
using IncidentManager.Application.Lessons;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>INV-06: decision entries on the investigation timeline.</summary>
public class DecisionEntryTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 16, 8, 0, 0, TimeSpan.Zero);

    private static (Case Case, TimelineEntry Entry) CaseWithDecision()
    {
        var c = Case.Open(2026, 1, "Phish", "Phishing", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic1", T0);
        var e = new TimelineEntry
        {
            CaseId = c.Id, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Decision, OccurredAtUtc = T0.AddHours(2),
            Description = "Reset credentials for all three users", Rationale = "Sign-in logs for two users are incomplete",
            OptionsConsidered = "Reset only the confirmed account", DecidedBy = "Incident Commander",
            CreatedBy = "ic1", CreatedAtUtc = T0.AddHours(3)
        };
        c.TimelineEntries.Add(e);
        return (c, e);
    }

    [Fact]
    public void A_decision_needs_a_rationale()
    {
        var ok = () => TimelineEntry.EnsureDecisionHasRationale(TimelineEntryType.Analysis, null);
        var missing = () => TimelineEntry.EnsureDecisionHasRationale(TimelineEntryType.Decision, " ");

        ok.Should().NotThrow();
        missing.Should().Throw<ArgumentException>().WithMessage("*why*");
    }

    [Fact]
    public void Editing_a_decision_keeps_its_details_on_the_new_version_and_they_are_hashed()
    {
        var (c, e) = CaseWithDecision();

        var next = c.EditInvestigationEntry(e.Id, TimelineEntryType.Decision, e.OccurredAtUtc, "Reset credentials for all three users today",
            null, "ic1", T0.AddHours(4), "Sign-in logs incomplete", null, "Incident Commander with Legal");

        next.Rationale.Should().Be("Sign-in logs incomplete");
        next.DecidedBy.Should().Be("Incident Commander with Legal");
        next.OptionsConsidered.Should().BeNull();
        next.BuildCanonicalContent().Should().Contain("|dec|Sign-in logs incomplete||Incident Commander with Legal");
    }

    [Fact]
    public void An_entry_that_is_not_a_decision_hashes_exactly_as_before()
    {
        var e = new TimelineEntry { Kind = TimelineKind.Investigation, Type = TimelineEntryType.Analysis, Description = "x", CreatedBy = "a" };

        e.BuildCanonicalContent().Should().NotContain("dec");
    }

    [Fact]
    public void Changing_a_decision_to_another_type_drops_its_details()
    {
        var (c, e) = CaseWithDecision();

        var next = c.EditInvestigationEntry(e.Id, TimelineEntryType.Analysis, e.OccurredAtUtc, "Reviewed", null, "ic1", T0.AddHours(4),
            "leftover", "leftover", "leftover");

        next.Rationale.Should().BeNull();
        next.DecidedBy.Should().BeNull();
    }

    [Fact]
    public void The_narrative_draft_lists_decisions_with_their_reason()
    {
        var (c, _) = CaseWithDecision();

        var md = CaseNarrative.Draft(c, _ => null, s => s.ToString(), T0.AddDays(1));

        md.Should().Contain("Decision: Reset credentials for all three users. Reason given: Sign-in logs for two users are incomplete.");
    }
}
