using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>INV-27: the brief says how far the record has moved on since it was written, and why to update it.</summary>
public class BriefFreshnessTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 1, 8, 0, 0, TimeSpan.Zero);
    private static readonly MilestoneLabels Labels = new(c => c.ToString(), s => s.ToString(), p => p.ToString(), m => m.ToString());

    private static Case NewCase() => Case.Open(2026, 7, "Phish", "Credential phishing", Classification.Incident,
        Severity.High, CaseOrigin.InternalDetection, "ic1", T0);

    private static void Entry(Case c, TimelineEntryType type, DateTimeOffset recorded, DateTimeOffset? occurred = null) =>
        c.TimelineEntries.Add(new TimelineEntry
        {
            CaseId = c.Id, Kind = TimelineKind.Investigation, Type = type, OccurredAtUtc = occurred ?? recorded,
            Description = type.ToString(), CreatedBy = "an1", CreatedAtUtc = recorded
        });

    [Fact]
    public void A_fresh_brief_has_nothing_to_report()
    {
        var c = NewCase();
        Entry(c, TimelineEntryType.Analysis, T0.AddHours(1));
        c.ChangePhase(CasePhase.Triage, null, "ic1", T0.AddHours(1));
        var brief = c.ReviseBrief("Lure reached Finance.", null, null, null, null, "ic1", T0.AddHours(2));

        var fresh = BriefFreshness.Since(c, brief, Labels);
        fresh.Count.Should().Be(0);
        fresh.Breakdown.Should().BeEmpty();
        fresh.Prompt.Should().BeNull();
    }

    [Fact]
    public void Changes_recorded_after_the_brief_are_counted_and_the_latest_turning_point_is_named()
    {
        var c = NewCase();
        var brief = c.ReviseBrief("Lure reached Finance.", null, null, null, null, "ic1", T0.AddHours(1));

        Entry(c, TimelineEntryType.Analysis, T0.AddHours(2));
        Entry(c, TimelineEntryType.Decision, T0.AddHours(3));
        c.ChangePhase(CasePhase.Containment, null, "ic1", T0.AddHours(4));
        // Recorded after the brief but dated before it: still news to whoever wrote the brief.
        Entry(c, TimelineEntryType.Analysis, T0.AddHours(5), occurred: T0);

        var fresh = BriefFreshness.Since(c, brief, Labels);

        fresh.Count.Should().Be(4);
        fresh.Breakdown.Should().Equal(("timeline entries", 3), ("phase change", 1));
        fresh.Prompt.Should().Be("The case moved to Containment after this version.", "the phase change is the latest turning point");
    }

    [Fact]
    public void A_decision_after_the_last_phase_change_is_the_reason_given()
    {
        var c = NewCase();
        var brief = c.ReviseBrief("Lure reached Finance.", null, null, null, null, "ic1", T0.AddHours(1));
        c.ChangePhase(CasePhase.Containment, null, "ic1", T0.AddHours(2));
        Entry(c, TimelineEntryType.Decision, T0.AddHours(3));

        BriefFreshness.Since(c, brief, Labels).Prompt.Should().Be("A decision was recorded after this version.");
    }

    [Fact]
    public void Routine_work_counts_but_does_not_prompt_an_update()
    {
        var c = NewCase();
        var brief = c.ReviseBrief("Lure reached Finance.", null, null, null, null, "ic1", T0.AddHours(1));
        Entry(c, TimelineEntryType.Analysis, T0.AddHours(2));
        c.ChangeSeverity(Severity.Critical, "NPI exposed", "ic1", T0.AddHours(3));

        var fresh = BriefFreshness.Since(c, brief, Labels);
        fresh.Count.Should().Be(2);
        fresh.Prompt.Should().BeNull();
    }
}
