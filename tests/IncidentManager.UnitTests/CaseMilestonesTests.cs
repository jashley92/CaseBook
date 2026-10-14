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
    public void A_corrected_materiality_call_reaches_the_timeline(/* REV-13 */)
    {
        var c = Case.Open(2026, 1, "Vendor", "Vendor incident", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "an1", T0);
        c.RecordMateriality(MaterialityStatus.Material, "CISO", T0.AddDays(3), "NPI involved", "lp1", T0.AddDays(3));
        c.RecordMateriality(MaterialityStatus.Material, "CISO", T0.AddDays(1), "NPI involved", "lp1", T0.AddDays(4));   // the real date
        c.RecordMateriality(MaterialityStatus.Material, "CISO", T0.AddDays(1), "NPI involved", "lp1", T0.AddDays(5));   // unchanged

        c.MaterialityChanges.Should().HaveCount(2, "a correction is recorded; a save that changes nothing isn't");
        var ms = CaseMilestones.Project(c, Labels).Where(m => m.Kind == MilestoneKind.Materiality).ToList();
        ms.Should().HaveCount(2);
        ms.Last().Title.Should().Be("Materiality determination revised (Material)");
        ms.Last().Detail.Should().StartWith("Decided by CISO on 2026-09-02.");
    }

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

    [Fact]
    public void Notices_converted_from_a_whole_case_report_are_not_the_editors_new_work(/* BUG-406 */)
    {
        var c = Case.Open(2026, 9, "Br", "Breach", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic1", T0);
        c.MarkReported(T0.AddDays(1), "lp1", T0.AddDays(1));   // reported as a whole by Legal
        var brief = c.ReviseBrief("Contained; NY notified.", null, null, null, null, "ic1", T0.AddDays(2))!;

        // Days later an analyst adds a data element; the whole-case report becomes notices (BUG-104).
        c.NoticesFromWholeReport(["NY", "NJ"], "lp1", T0.AddDays(1), "an1", T0.AddDays(5));

        c.JurisdictionNotices.Should().OnlyContain(n => n.CreatedBy == "lp1" && n.CreatedAtUtc == T0.AddDays(1));
        var notices = CaseMilestones.Project(c, Labels).Where(m => m.Key.StartsWith("notice:", StringComparison.Ordinal)).ToList();
        notices.Should().HaveCount(2).And.OnlyContain(m => m.Actor == "lp1" && m.RecordedAtUtc == null);
        BriefFreshness.Since(c, brief, Labels).Count.Should().Be(0, "nothing new was recorded");
    }

    [Fact]
    public void Backdated_notices_and_completions_carry_when_they_were_recorded(/* BUG-364, BUG-365 */)
    {
        var c = Case.Open(2026, 9, "Br", "Breach", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic1", T0);
        c.RecordNotice("NY", T0.AddDays(1), "lp1", T0.AddDays(3));          // entered two days after the fact
        c.RecordNotice("CA", T0.AddDays(2), "lp1", T0.AddDays(2));          // entered as it happened
        c.ReportedFromNotices(["NY", "CA"], "lp1", T0.AddDays(3));
        c.ActionItems.Add(new ActionItem
        {
            CaseId = c.Id, Title = "Reset creds", Status = ActionItemStatus.Done, Owner = "rr1", CompletedBy = "an2",
            CompletedAtUtc = T0.AddHours(5), CompletionRecordedAtUtc = T0.AddDays(1), ModifiedBy = "ic1"
        });
        c.ActionItems.Add(new ActionItem
        {
            CaseId = c.Id, Title = "Old task", Status = ActionItemStatus.Done, Owner = "rr1", CompletedAtUtc = T0.AddHours(6), ModifiedBy = "ic1"
        });

        var ms = CaseMilestones.Project(c, Labels);

        ms.Single(m => m.Title == "Notified NY").RecordedAtUtc.Should().Be(T0.AddDays(3));
        ms.Single(m => m.Title == "Notified CA").RecordedAtUtc.Should().BeNull("it was entered as it happened");
        var reported = ms.Single(m => m.Key.StartsWith("reported:", StringComparison.Ordinal));
        reported.AtUtc.Should().Be(T0.AddDays(2));
        reported.RecordedAtUtc.Should().Be(T0.AddDays(3), "the last notice was entered then");

        var done = ms.Single(m => m.Title == "Task done: Reset creds");
        done.Actor.Should().Be("an2", "credited to who completed it, not who edited the task last");
        done.RecordedAtUtc.Should().Be(T0.AddDays(1));
        var old = ms.Single(m => m.Title == "Task done: Old task");
        old.Actor.Should().Be("ic1", "a task completed before either was kept falls back as before");
        old.RecordedAtUtc.Should().BeNull();
    }
}
