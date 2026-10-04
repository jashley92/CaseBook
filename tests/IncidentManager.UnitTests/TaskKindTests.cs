using FluentAssertions;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>INV-13: task kinds and the "no tasks left open" gate check.</summary>
public class TaskKindTests
{
    [Fact]
    public void A_general_task_hashes_exactly_as_before_and_a_kind_is_folded_in()
    {
        var t = new ActionItem { CaseId = Guid.Empty, Title = "Block domains" };
        var before = t.BuildCanonicalContent();

        before.Should().NotContain("kind");
        t.Kind = TaskKind.Contain;
        t.BuildCanonicalContent().Should().Be(before + "|kind|2");
    }

    [Fact]
    public void Each_phase_kind_belongs_to_its_phase()
    {
        TaskKind.Investigate.Phase().Should().Be(CasePhase.Triage);
        TaskKind.Contain.Phase().Should().Be(CasePhase.Containment);
        TaskKind.Eradicate.Phase().Should().Be(CasePhase.Eradication);
        TaskKind.Recover.Phase().Should().Be(CasePhase.Recovery);
        TaskKind.Notify.Phase().Should().BeNull();
        TaskKind.General.Phase().Should().BeNull();
    }

    [Fact]
    public void A_task_result_is_logged_as_what_the_task_was()
    {
        // HR-10: no more "Other" for a containment task's result.
        TaskKind.Investigate.ResultType().Should().Be(TimelineEntryType.Analysis);
        TaskKind.Contain.ResultType().Should().Be(TimelineEntryType.Containment);
        TaskKind.Eradicate.ResultType().Should().Be(TimelineEntryType.Eradication);
        TaskKind.Recover.ResultType().Should().Be(TimelineEntryType.Recovery);
        TaskKind.Notify.ResultType().Should().Be(TimelineEntryType.Communication);
        TaskKind.General.ResultType().Should().Be(TimelineEntryType.Other);
    }

    [Fact]
    public void The_no_open_tasks_check_passes_only_when_nothing_is_open()
    {
        var facts = new GateCaseFacts(true, true, true, true, true, 1, 1, 1, 1, true);

        GateCheckRegistry.IsSatisfied(GateCheckKeys.NoOpenTasks, facts with { OpenTaskCount = 0 }, null).Should().BeTrue();
        GateCheckRegistry.IsSatisfied(GateCheckKeys.NoOpenTasks, facts with { OpenTaskCount = 2 }, null).Should().BeFalse();
    }

    [Fact]
    public void NotificationsRecorded_fails_only_while_a_notification_clock_runs_unreported()
    {
        var facts = new GateCaseFacts(true, true, true, true, true, 1, 1, 1, 1, true);

        GateCheckRegistry.IsSatisfied(GateCheckKeys.NotificationsRecorded, facts, null).Should().BeTrue();
        GateCheckRegistry.IsSatisfied(GateCheckKeys.NotificationsRecorded, facts with { NotificationPending = true }, null)
            .Should().BeFalse();
    }
}
