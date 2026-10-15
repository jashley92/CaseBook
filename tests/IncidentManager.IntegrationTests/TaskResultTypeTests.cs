using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Components.Pages.CaseTabs;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-508: the Tasks tab and Now/Next log a task's result as the same type.</summary>
public class TaskResultTypeTests
{
    private static readonly IReadOnlyList<TimelineEntryType> All = Enum.GetValues<TimelineEntryType>();

    [Fact]
    public void A_result_is_logged_as_what_the_task_was()
    {
        CaseTasksTab.ResultTypeFor(new ActionItem { Kind = TaskKind.Contain }, All).Should().Be(TimelineEntryType.Containment);
        CaseTasksTab.ResultTypeFor(new ActionItem { Kind = TaskKind.General }, All).Should().Be(TimelineEntryType.Other);
    }

    [Fact]
    public void A_questions_answer_is_analysis()
    {
        CaseTasksTab.ResultTypeFor(new ActionItem { Kind = TaskKind.Contain, RaisedFromBriefId = Guid.NewGuid() }, All)
            .Should().Be(TimelineEntryType.Analysis);
    }

    [Fact]
    public void A_hidden_type_becomes_the_first_offered()
    {
        var offered = new[] { TimelineEntryType.Analysis, TimelineEntryType.Other };
        CaseTasksTab.ResultTypeFor(new ActionItem { Kind = TaskKind.Eradicate }, offered).Should().Be(TimelineEntryType.Analysis);
        CaseTasksTab.ResultTypeFor(new ActionItem { Kind = TaskKind.Eradicate }, []).Should().Be(TimelineEntryType.Eradication);
    }
}
