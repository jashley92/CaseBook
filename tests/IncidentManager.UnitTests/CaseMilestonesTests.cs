using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>INV-01: response milestones projected onto the timeline from the case's existing records.</summary>
public class CaseMilestonesTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 1, 8, 0, 0, TimeSpan.Zero);

    private static readonly MilestoneLabels Labels = new(
        c => c?.ToString() ?? "Complex Event",
        s => s == Severity.Critical ? "SEV-1" : s.ToString(),
        p => p.ToString(),
        m => m.ToString());

    [Fact]
    public void Transitions_become_milestones_in_order_with_reason_and_actor()
    {
        var c = Case.Open(2026, 7, "Phish", "Credential phishing", Classification.AdverseEvent,
            Severity.High, CaseOrigin.InternalDetection, "ic1", T0);
        c.ChangePhase(CasePhase.Triage, null, "an1", T0.AddHours(1));
        c.ChangeSeverity(Severity.Critical, "Payroll in scope", "ic1", T0.AddHours(2));
        c.Reclassify(Classification.Breach, "NPI exposed", "ic1", T0.AddHours(3));
        c.RecordGatePassage(StageGateTrigger.EscalateToBreach, overridden: true, "Legal asked us to proceed",
            null, "detail", "ic1", T0.AddHours(3));

        var ms = CaseMilestones.Project(c, Labels);

        ms.Select(m => m.Kind).Should().Equal(
            MilestoneKind.Opened, MilestoneKind.Phase, MilestoneKind.Severity,
            MilestoneKind.Classification, MilestoneKind.Gate);
        ms[0].Title.Should().Be("Case opened as AdverseEvent · High");
        ms[1].Title.Should().Be("Phase New → Triage");
        ms[1].Actor.Should().Be("an1");
        ms[2].Title.Should().Be("Severity High → SEV-1");
        ms[2].Detail.Should().Be("Payroll in scope");
        ms[3].Title.Should().Be("Classification AdverseEvent → Breach");
        ms[4].Title.Should().Be("Breach escalation gate overridden");
        ms[4].Detail.Should().Be("Justification: Legal asked us to proceed");
        ms[4].Flagged.Should().BeTrue();
        ms.Select(m => m.Key).Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void A_complex_event_opens_without_a_classification_and_its_promotion_is_a_milestone()
    {
        var c = Case.Open(2026, 8, "Odd", "Odd beaconing", null, Severity.Medium, CaseOrigin.InternalDetection, "an1", T0);
        c.Reclassify(Classification.Incident, "Confirmed C2", "an1", T0.AddHours(1));

        var ms = CaseMilestones.Project(c, Labels);

        ms[0].Title.Should().Be("Case opened as Complex Event · Medium");
        ms.Should().ContainSingle(m => m.Kind == MilestoneKind.Classification)
            .Which.Title.Should().Be("Classification Complex Event → Incident");
    }

    [Fact]
    public void Materiality_reported_tasks_evidence_and_final_reports_are_included()
    {
        var c = Case.Open(2026, 9, "Br", "Breach", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic1", T0);
        c.RecordMateriality(MaterialityStatus.Material, "Disclosure Committee", T0.AddDays(1), "NPI of NY residents", "lp1", T0.AddDays(1));
        c.MarkReported(T0.AddDays(2), "lp1", T0.AddDays(2));
        c.ActionItems.Add(new ActionItem { CaseId = c.Id, Title = "Reset creds", Status = ActionItemStatus.Done, CompletedAtUtc = T0.AddHours(5), Owner = "rr1" });
        c.ActionItems.Add(new ActionItem { CaseId = c.Id, Title = "Still open", Status = ActionItemStatus.Open });
        var shot = new Evidence { CaseId = c.Id, OriginalFileName = "shot.png", CreatedAtUtc = T0.AddHours(1), CreatedBy = "an1" };
        var log = new Evidence { CaseId = c.Id, OriginalFileName = "signin.csv", CreatedAtUtc = T0.AddHours(2), CreatedBy = "an1" };
        c.Evidence.Add(shot);
        c.Evidence.Add(log);
        c.AddEventStep(T0, [], null, null, null, "Step with a screenshot", null, "an1", T0.AddHours(1), evidenceId: shot.Id);
        c.Reports.Add(new Report { CaseId = c.Id, Version = 2, IsFinal = true, ApprovedBy = "ic1", ApprovedAtUtc = T0.AddDays(3) });
        c.Reports.Add(new Report { CaseId = c.Id, Version = 1 });

        var ms = CaseMilestones.Project(c, Labels);

        ms.Should().ContainSingle(m => m.Kind == MilestoneKind.Materiality).Which.Detail
            .Should().Be("Decided by Disclosure Committee on 2026-09-02. NPI of NY residents");
        ms.Should().ContainSingle(m => m.Kind == MilestoneKind.Reported).Which.AtUtc.Should().Be(T0.AddDays(2));
        ms.Should().ContainSingle(m => m.Kind == MilestoneKind.TaskDone).Which.Title.Should().Be("Task done: Reset creds");
        // The screenshot already shows on its timeline entry; only the other file becomes a milestone.
        ms.Should().ContainSingle(m => m.Kind == MilestoneKind.EvidenceAdded).Which.Title.Should().Be("Evidence added: signin.csv");
        ms.Should().ContainSingle(m => m.Kind == MilestoneKind.ReportFinal).Which.Title.Should().Be("Case report v2 approved as final");
    }
}
