using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>INV-31: who took command, joined, changed role or left is on the timeline, not only in the audit trail.</summary>
public class CommandMilestoneTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 1, 8, 0, 0, TimeSpan.Zero);
    private static readonly MilestoneLabels Labels = new(c => c.ToString(), s => s.ToString(), p => p.ToString(), m => m.ToString());

    private static Case NewCase() => Case.Open(2026, 7, "Phish", "Credential phishing", Classification.Incident,
        Severity.High, CaseOrigin.InternalDetection, "ic1", T0);

    private static List<string> Command(Case c) =>
        CaseMilestones.Project(c, Labels).Where(m => m.Kind == MilestoneKind.Command).OrderBy(m => m.AtUtc).Select(m => m.Title).ToList();

    [Fact]
    public void Joining_taking_command_handing_over_and_leaving_are_milestones()
    {
        var c = NewCase();
        c.Assign("ivy", "Ivy Commander", CaseAssignmentRole.IncidentCommander, "mgr", T0.AddHours(1));
        c.Assign("alex", "Alex Analyst", CaseAssignmentRole.Analyst, "ivy", T0.AddHours(2));
        c.Assign("sam", "Sam Admin", CaseAssignmentRole.IncidentCommander, "mgr", T0.AddHours(26));   // Ivy hands over
        c.Unassign("alex", "sam", T0.AddHours(30));

        Command(c).Should().Equal(
            "Ivy Commander is incident commander",
            "Alex Analyst joined as analyst",
            "Sam Admin is incident commander, taking over from Ivy Commander",
            "Alex Analyst is no longer on the case (was analyst)");
        c.IncidentCommander.Should().Be("sam");
    }

    [Fact]
    public void Re_assigning_someone_to_the_role_they_hold_records_nothing()
    {
        var c = NewCase();
        c.Assign("alex", "Alex Analyst", CaseAssignmentRole.Analyst, "ivy", T0.AddHours(1));
        c.Assign("alex", "Alex Analyst", CaseAssignmentRole.Analyst, "ivy", T0.AddHours(2));

        c.AssignmentChanges.Should().ContainSingle();
    }
}
