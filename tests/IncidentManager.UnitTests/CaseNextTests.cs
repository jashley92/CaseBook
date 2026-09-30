using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>INV-25: next steps are the case's open tasks — one list, in one order, wherever it's read.</summary>
public class CaseNextTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 1, 8, 0, 0, TimeSpan.Zero);

    private static Case NewCase() => Case.Open(2026, 7, "Phish", "Credential phishing", Classification.Incident,
        Severity.High, CaseOrigin.InternalDetection, "ic1", T0);

    private static ActionItem Task(Case c, string title, DateTimeOffset? due = null, TaskKind kind = TaskKind.General,
        string? owner = null, ActionItemStatus status = ActionItemStatus.Open)
    {
        var t = new ActionItem { CaseId = c.Id, Title = title, DueAtUtc = due, Kind = kind, Owner = owner, Status = status, CreatedAtUtc = T0 };
        c.ActionItems.Add(t);
        return t;
    }

    [Fact]
    public void Overdue_work_leads_then_work_before_the_next_phase_then_by_due_date()
    {
        var c = NewCase();
        c.ChangePhase(CasePhase.Containment, null, "ic1", T0);   // so the next phase is Eradication
        Task(c, "Later, general", T0.AddDays(3));
        Task(c, "Before eradication", T0.AddDays(5), TaskKind.Contain);
        Task(c, "Overdue", T0.AddHours(-1), TaskKind.Recover);
        Task(c, "Soon, general", T0.AddDays(1));
        Task(c, "No date");
        Task(c, "Done already", T0.AddHours(-5), status: ActionItemStatus.Done);

        CaseNext.Open(c, T0).Select(t => t.Title).Should().Equal(
            "Overdue", "Before eradication", "Soon, general", "Later, general", "No date");
    }

    [Fact]
    public void The_snapshot_lists_the_open_tasks_with_their_owners()
    {
        var c = NewCase();
        Task(c, "Block the domains", T0.AddDays(1), owner: "analyst1");
        Task(c, "Confirm the drafts", T0.AddDays(2));

        CaseNext.Snapshot(c, T0, u => u == "analyst1" ? "Alex Analyst" : u)
            .Should().Be("- Block the domains (Alex Analyst)\n- Confirm the drafts");
        CaseNext.Snapshot(NewCase(), T0, u => u).Should().BeNull();
    }

    [Theory]
    [InlineData("- One?\n- Two?", new[] { "One?", "Two?" })]
    [InlineData("1. One?\n2) Two?\n", new[] { "One?", "Two?" })]
    [InlineData("* One?", new[] { "One?" })]
    public void Open_questions_written_as_a_list_split_into_questions(string text, string[] expected) =>
        CaseNext.Questions(text).Should().Equal(expected);

    [Theory]
    [InlineData("Whether the other users' sessions were used.")]
    [InlineData("- One?\nand some prose")]
    [InlineData("  ")]
    public void Open_questions_written_as_prose_are_left_as_written(string text) =>
        CaseNext.Questions(text).Should().BeNull();

    [Fact]
    public void A_question_is_raised_as_a_task_once_while_that_task_is_open()
    {
        var c = NewCase();
        c.ReviseBrief("Lure reached Finance.", null, null, "- Were the others' credentials used?", null, "ic1", T0);

        var t = c.RaiseTaskFromQuestion("Were the others' credentials used?", "an1", T0.AddHours(1));
        t.RaisedFromBriefId.Should().Be(c.Briefs.Single().Id);
        t.Description.Should().Be("Raised from an open question in the brief (v1).");

        var again = () => c.RaiseTaskFromQuestion("were the others' credentials used?", "an1", T0.AddHours(2));
        again.Should().Throw<InvalidOperationException>();

        t.Status = ActionItemStatus.Done;
        c.RaiseTaskFromQuestion("Were the others' credentials used?", "an1", T0.AddHours(3))
            .Should().NotBeSameAs(t, "the earlier task is done, so the question can be followed up again");
    }

    [Fact]
    public void A_task_not_raised_from_the_brief_keeps_its_hash()
    {
        var c = NewCase();
        var t = Task(c, "Block the domains", T0.AddDays(1), TaskKind.Contain, "analyst1");
        var before = t.BuildCanonicalContent();
        before.Should().NotContain("brief");

        t.RaisedFromBriefId = Guid.NewGuid();
        t.BuildCanonicalContent().Should().StartWith(before).And.EndWith($"|brief|{t.RaisedFromBriefId}");
    }
}
