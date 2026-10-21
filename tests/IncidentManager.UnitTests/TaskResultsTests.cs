using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Entities;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>HR-02: task results and who completed a task.</summary>
public class TaskResultsTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void CompletedBy_is_hashed_only_when_set_so_existing_rows_keep_their_hash()
    {
        var t = new ActionItem { CaseId = Guid.NewGuid(), Title = "Disable the account" };
        var before = t.BuildCanonicalContent();

        t.CompletedBy = "dev:analyst";

        t.BuildCanonicalContent().Should().Be(before + "|by|dev:analyst");
    }

    [Theory]   // FR-63: new reasons are kept as "Canceled: "; ones kept before as "Cancelled: " still read as reasons
    [InlineData("Canceled: duplicate", true, "Canceled: duplicate")]
    [InlineData("Cancelled: duplicate", true, "Canceled: duplicate")]
    [InlineData("Result: contained", false, "Result: contained")]
    [InlineData("cancelled by the vendor", false, "cancelled by the vendor")]
    public void A_cancel_reason_is_read_in_either_spelling_and_shown_in_the_current_one(string body, bool isReason, string shown)
    {
        CaseService.CancelledPrefix.Should().Be("Canceled: ");
        CaseService.IsCancelReason(body).Should().Be(isReason);
        CaseService.CancelReasonDisplay(body).Should().Be(shown);
    }

    [Fact]
    public void The_latest_result_per_task_wins_and_other_comments_are_ignored()
    {
        var task = Guid.NewGuid();
        var other = Guid.NewGuid();
        var comments = new[]
        {
            new ActionItemComment { ActionItemId = task, Body = "Result: first answer", CreatedAtUtc = T0, CreatedBy = "a" },
            new ActionItemComment { ActionItemId = task, Body = "Checked with AP", CreatedAtUtc = T0.AddHours(1), CreatedBy = "a" },
            new ActionItemComment { ActionItemId = task, Body = "Result: second answer", CreatedAtUtc = T0.AddHours(2), CreatedBy = "b" },
            new ActionItemComment { ActionItemId = other, Body = "Resulting work is pending", CreatedAtUtc = T0, CreatedBy = "a" },
        };

        var latest = TaskResults.Latest(comments);

        latest.Should().ContainSingle();
        latest[task].Should().Be(new TaskResult("second answer", T0.AddHours(2), "b"));
    }

    [Fact]
    public void Excerpt_keeps_one_line_and_trims_long_text()
    {
        TaskResults.Excerpt("Disabled 10:14.\nSessions revoked 10:16.").Should().Be("Disabled 10:14. Sessions revoked 10:16.");
        TaskResults.Excerpt(new string('x', 200), 20).Should().HaveLength(20).And.EndWith("…");
    }

    [Fact]
    public void A_done_task_prints_when_and_by_whom()
    {
        new ReportActionItemRow("Disable", "Ivy", null, "Done", "Disabled", T0, "Dev Analyst").StatusLine
            .Should().Be("Done, 2026-10-01 10:00 UTC by Dev Analyst");
        new ReportActionItemRow("Disable", "Ivy", null, "Open").StatusLine.Should().Be("Open");
    }
}
