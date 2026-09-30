using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>INV-21: the handoff's "done since the last handoff" lists the team's work, not the adversary's.</summary>
public class HandoffDraftTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 1, 8, 0, 0, TimeSpan.Zero);

    private static readonly MilestoneLabels Labels = new(
        c => c?.ToString() ?? "Complex Event", s => s.ToString(), p => p.ToString(), m => m.ToString());

    private static Case NewCase() => Case.Open(2026, 7, "Phish", "Credential phishing", Classification.AdverseEvent,
        Severity.High, CaseOrigin.InternalDetection, "ic1", T0);

    private static TimelineEntry Entry(Case c, TimelineKind kind, TimelineEntryType type, string text, DateTimeOffset at) =>
        new() { CaseId = c.Id, Kind = kind, Type = type, Description = text, OccurredAtUtc = at, CreatedAtUtc = at };

    [Fact]
    public void Event_steps_are_counted_not_listed_as_done()
    {
        var c = NewCase();
        c.TimelineEntries.Add(Entry(c, TimelineKind.Event, TimelineEntryType.Other, "jdoe entered credentials", T0.AddHours(1)));
        c.TimelineEntries.Add(Entry(c, TimelineKind.Event, TimelineEntryType.Other, "Mailbox searched", T0.AddHours(2)));
        c.TimelineEntries.Add(Entry(c, TimelineKind.Investigation, TimelineEntryType.Analysis, "Reviewed audit logs", T0.AddHours(3)));

        var done = HandoffDraft.DoneSince(c, Labels, s => s);

        done.Should().Be("- Reviewed audit logs\n- Learned: 2 event steps added to the timeline");
    }

    [Fact]
    public void Decisions_milestones_and_done_tasks_are_listed_in_the_order_they_happened()
    {
        var c = NewCase();
        c.ChangePhase(CasePhase.Containment, "Sessions revoked", "ic1", T0.AddHours(4));
        var decision = Entry(c, TimelineKind.Investigation, TimelineEntryType.Decision, "Reset all three users", T0.AddHours(2));
        decision.Rationale = "Logs incomplete";
        c.TimelineEntries.Add(decision);
        c.ActionItems.Add(new ActionItem
        {
            CaseId = c.Id, Title = "Send user list to Legal", Status = ActionItemStatus.Done, CompletedAtUtc = T0.AddHours(3)
        });

        var done = HandoffDraft.DoneSince(c, Labels, s => s);

        done.Should().Be("- Decision: Reset all three users\n- Task done: Send user list to Legal\n- Phase New → Containment");
    }

    [Fact]
    public void Only_what_was_recorded_after_the_last_handoff_is_included()
    {
        var c = NewCase();
        c.TimelineEntries.Add(Entry(c, TimelineKind.Investigation, TimelineEntryType.Analysis, "Before", T0.AddHours(1)));
        c.TimelineEntries.Add(Entry(c, TimelineKind.Investigation, TimelineEntryType.Handoff, "Handed to an1", T0.AddHours(2)));
        c.TimelineEntries.Add(Entry(c, TimelineKind.Investigation, TimelineEntryType.Analysis, "After", T0.AddHours(3)));

        HandoffDraft.DoneSince(c, Labels, s => s).Should().Be("- After");
    }

    [Fact]
    public void An_edit_after_the_handoff_does_not_bring_an_older_entry_back()
    {
        var c = NewCase();
        var original = Entry(c, TimelineKind.Investigation, TimelineEntryType.Analysis, "Old", T0.AddHours(1));
        original.IsCurrent = false;
        c.TimelineEntries.Add(original);
        c.TimelineEntries.Add(Entry(c, TimelineKind.Investigation, TimelineEntryType.Handoff, "Handed to an1", T0.AddHours(2)));
        var edited = Entry(c, TimelineKind.Investigation, TimelineEntryType.Analysis, "Old, reworded", T0.AddHours(1));
        edited.CreatedAtUtc = T0.AddHours(3);
        edited.SupersedesEntryId = original.Id;
        c.TimelineEntries.Add(edited);

        HandoffDraft.DoneSince(c, Labels, s => s).Should().BeNull();
    }
}
