using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

public class CaseTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 8, 12, 0, 0, TimeSpan.Zero);

    private static Case NewCase() => Case.Open(
        2026, 1, "Phishing Wave", "Phishing wave against finance",
        Classification.AdverseEvent, Severity.Medium, CaseOrigin.InternalDetection, "analyst1", Now);

    [Fact]
    public void Open_formats_case_number_and_seeds_history()
    {
        var c = NewCase();

        c.CaseNumber.Should().Be("2026-01_Phishing_Wave");
        c.Phase.Should().Be(CasePhase.New);
        c.Classification.Should().Be(Classification.AdverseEvent);
        c.ClassificationChanges.Should().ContainSingle().Which.To.Should().Be(Classification.AdverseEvent);
        c.StatusChanges.Should().ContainSingle().Which.To.Should().Be(CasePhase.New);
    }

    [Fact]
    public void Reclassify_escalation_records_history_and_updates_current()
    {
        var c = NewCase();

        c.Reclassify(Classification.Incident, "Confirmed malicious activity", "ic1", Now.AddHours(1));
        c.Reclassify(Classification.Breach, "NPI confirmed exfiltrated", "ic1", Now.AddHours(2));

        c.Classification.Should().Be(Classification.Breach);
        c.ClassificationChanges.Should().HaveCount(3); // initial + 2 escalations
        c.ClassificationChanges[^1].From.Should().Be(Classification.Incident);
        c.ClassificationChanges[^1].To.Should().Be(Classification.Breach);
    }

    [Fact]
    public void EditNote_supersedes_the_prior_version_without_losing_it()
    {
        var c = NewCase();
        c.Notes.Add(new AnalystNote { CaseId = c.Id, Body = "Initial finding", CreatedBy = "analyst1", CreatedAtUtc = Now });
        var original = c.Notes.Single();

        var edited = c.EditNote(original.Id, "Revised finding", "analyst1", Now.AddHours(1));

        // Both versions are retained; only the newest is current.
        c.Notes.Should().HaveCount(2);
        original.IsCurrent.Should().BeFalse();
        edited.IsCurrent.Should().BeTrue();
        edited.Version.Should().Be(2);
        edited.SupersedesNoteId.Should().Be(original.Id);
        c.Notes.Single(n => n.IsCurrent).Body.Should().Be("Revised finding");
    }

    [Fact]
    public void EditNote_on_a_missing_or_superseded_note_throws()
    {
        var c = NewCase();

        var act = () => c.EditNote(Guid.NewGuid(), "x", "analyst1", Now);

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void AddTechnique_normalises_the_id_and_dedupes_by_technique()
    {
        var c = NewCase();

        c.AddTechnique("t1566.001", "Spearphishing Attachment", MitreTactic.InitialAccess, "analyst1", Now);
        // Same ID (case-insensitive) updates rather than duplicating.
        c.AddTechnique("T1566.001", "Phishing: Spearphishing Attachment", MitreTactic.InitialAccess, "analyst1", Now.AddMinutes(5));

        c.Techniques.Should().ContainSingle();
        var t = c.Techniques.Single();
        t.TechniqueId.Should().Be("T1566.001");
        t.Name.Should().Be("Phishing: Spearphishing Attachment");
    }

    [Fact]
    public void AddTechnique_rejects_a_malformed_attack_id()
    {
        var c = NewCase();

        var act = () => c.AddTechnique("not-a-technique", "x", MitreTactic.Impact, "analyst1", Now);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Archive_is_blocked_while_under_legal_hold()
    {
        var c = NewCase();
        c.PlaceLegalHold("legal1", Now);

        var act = () => c.Archive("admin1", Now.AddHours(1));

        act.Should().Throw<InvalidOperationException>();
        c.IsArchived.Should().BeFalse();

        // Releasing the hold allows archival.
        c.ReleaseLegalHold("legal1", Now.AddHours(2));
        c.Archive("admin1", Now.AddHours(3));
        c.IsArchived.Should().BeTrue();
    }

    [Fact]
    public void An_archived_case_is_restored_before_anything_that_could_start_its_notification_clock_changes(/* BUG-150 */)
    {
        var c = Case.Open(2026, 1, "Vendor", "Vendor incident", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "analyst1", Now);
        c.Archive("admin1", Now.AddHours(1));

        var acts = new Action[]
        {
            () => c.RecordMateriality(MaterialityStatus.Material, "CISO", Now.AddDays(3), "Material", "analyst1", Now.AddDays(3)),
            () => c.Reclassify(Classification.Breach, "Data left", "analyst1", Now.AddDays(3)),
            () => c.SetImpactAssessment(1200, ["ssn"], "NY", "analyst1", Now.AddDays(3)),
        };
        foreach (var act in acts) act.Should().Throw<InvalidOperationException>().WithMessage("*archived*Restore it*");
        c.Materiality.Status.Should().Be(MaterialityStatus.Undetermined);
        c.Classification.Should().Be(Classification.Incident);

        c.Unarchive("admin1", Now.AddDays(3));
        c.RecordMateriality(MaterialityStatus.Material, "CISO", Now.AddDays(3), "Material", "analyst1", Now.AddDays(3));
        c.Materiality.Status.Should().Be(MaterialityStatus.Material);
    }

    [Fact]
    public void An_archived_case_keeps_its_notices(/* BUG-190 */)
    {
        var c = Case.Open(2026, 1, "Vendor", "Vendor incident", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "analyst1", Now);
        c.RecordNotice("NY", Now.AddHours(2), "analyst1", Now.AddHours(2));
        c.RecordNotice("CA", Now.AddHours(3), "analyst1", Now.AddHours(3));
        c.Archive("admin1", Now.AddDays(1));

        c.Invoking(x => x.RemoveNotice("CA", "analyst1", Now.AddDays(2)))
            .Should().Throw<InvalidOperationException>().WithMessage("*archived*Restore it*");
        c.JurisdictionNotices.Should().HaveCount(2);
    }

    [Fact]
    public void A_jurisdiction_code_with_a_separator_cannot_corrupt_the_kept_jurisdictions(/* BUG-404 */)
    {
        var c = Case.Open(2026, 1, "Vendor", "Vendor incident", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "analyst1", Now);
        c.Invoking(x => x.RecordNotice("NY;CA", Now.AddHours(1), "analyst1", Now.AddHours(1)))
            .Should().Throw<ArgumentException>().WithMessage("*comma or semicolon*");
        c.JurisdictionNotices.Should().BeEmpty();

        // A code from an element stored with ";" before this release is split when kept, not read as the elements part.
        c.MarkReported(Now.AddHours(2), "analyst1", Now.AddHours(2), ["NY;CA"]);
        c.FrozenJurisdictions.Should().Equal("CA", "NY");
        c.FrozenElementKeys.Should().BeEmpty();
    }

    [Fact]
    public void A_two_person_hold_release_needs_a_reason_and_a_different_approver(/* F-12 */)
    {
        var c = NewCase();
        c.Invoking(x => x.RequestLegalHoldRelease("why", "legal1", Now)).Should().Throw<InvalidOperationException>("no hold yet");
        c.PlaceLegalHold("legal1", Now);

        c.Invoking(x => x.RequestLegalHoldRelease("  ", "legal1", Now)).Should().Throw<ArgumentException>();
        c.RequestLegalHoldRelease("Matter closed", "legal1", Now.AddHours(1));
        c.LegalHoldReleasePending.Should().BeTrue();

        c.Invoking(x => x.ApproveLegalHoldRelease("LEGAL1", Now.AddHours(2))).Should().Throw<InvalidOperationException>();
        c.ApproveLegalHoldRelease("legal2", Now.AddHours(2));
        c.LegalHold.Should().BeFalse();
        c.LegalHoldReleasePending.Should().BeFalse();

        // The pending request isn't case content: it stays out of the tamper-evident row hash.
        var before = c.BuildCanonicalContent();
        c.PlaceLegalHold("legal1", Now.AddHours(3));
        c.RequestLegalHoldRelease("again", "legal1", Now.AddHours(4));
        var withRequest = c.BuildCanonicalContent();
        c.CancelLegalHoldReleaseRequest("legal1", Now.AddHours(5));
        c.BuildCanonicalContent().Should().Be(withRequest);
        withRequest.Should().NotBe(before, "the hold itself is canonical");
    }

    [Fact]
    public void Reclassify_requires_a_reason()
    {
        var c = NewCase();

        var act = () => c.Reclassify(Classification.Incident, "   ", "ic1", Now);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Reclassify_to_same_value_is_a_noop()
    {
        var c = NewCase();

        c.Reclassify(Classification.AdverseEvent, "no change", "ic1", Now);

        c.ClassificationChanges.Should().ContainSingle();
    }

    [Fact]
    public void ChangePhase_captures_lifecycle_timestamps()
    {
        var c = NewCase();

        c.ChangePhase(CasePhase.Containment, "Isolated host", "analyst1", Now.AddHours(1));
        c.ChangePhase(CasePhase.Recovery, "Restored service", "analyst1", Now.AddHours(3));
        c.ChangePhase(CasePhase.Closed, "Post-incident complete", "ic1", Now.AddHours(5));

        c.ContainedAtUtc.Should().Be(Now.AddHours(1));
        c.ResolvedAtUtc.Should().Be(Now.AddHours(3));
        c.ClosedAtUtc.Should().Be(Now.AddHours(5));
        c.StatusChanges.Should().HaveCount(4); // initial New + 3 transitions
    }

    [Fact]
    public void Editing_a_referral_keeps_when_it_was_referred_and_by_whom(/* REV-12 */)
    {
        var c = NewCase();
        c.ReferToLegal("ic1", "legal@example.com", "NPI", Now.AddHours(1));

        c.ReferToLegal("an2", "privacy@example.com", "NPI of NY residents", Now.AddDays(8));

        c.LegalReferral!.ReferredAtUtc.Should().Be(Now.AddHours(1));
        c.LegalReferral.ReferredBy.Should().Be("ic1");
        c.LegalReferral.ReferredToContact.Should().Be("privacy@example.com");
        c.LegalReferral.RegulatoryRelevanceNote.Should().Be("NPI of NY residents");
    }

    [Fact]
    public void ReferToLegal_captures_referral_without_deadlines()
    {
        var c = NewCase();

        c.ReferToLegal("ic1", "legal@example.com", "NY resident NPI potentially involved", Now.AddHours(1));

        c.LegalReferral.IsReferred.Should().BeTrue();
        c.LegalReferral.ReferredToContact.Should().Be("legal@example.com");
        c.LegalReferral.ReferredAtUtc.Should().Be(Now.AddHours(1));
    }

    [Fact]
    public void MarkReported_sets_the_milestone_and_can_be_cleared()
    {
        var c = NewCase();
        c.MarkReported(Now.AddHours(2), "ic1", Now.AddHours(2));
        c.ReportedAtUtc.Should().Be(Now.AddHours(2));

        c.ClearReported("ic1", Now.AddHours(3));
        c.ReportedAtUtc.Should().BeNull();
    }

    [Fact]
    public void MarkReported_rejects_a_future_or_pre_detection_time()
    {
        var c = NewCase(); // DetectedAtUtc == Now (set on Open)
        var future = () => c.MarkReported(Now.AddDays(1), "ic1", Now);
        future.Should().Throw<ArgumentException>();

        var beforeDetection = () => c.MarkReported(Now.AddHours(-1), "ic1", Now);
        beforeDetection.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void RecordMateriality_is_refused_below_the_incident_rung()
    {
        var c = NewCase(); // opens as AdverseEvent
        var act = () => c.RecordMateriality(MaterialityStatus.UnderReview, null, null, null, "legal1", Now);
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void The_detected_time_cant_move_past_a_regulator_notice_or_a_completed_task(/* BUG-111 */)
    {
        var c = NewCase();
        var detected = c.DetectedAtUtc!.Value;
        c.RecordNotice("NY", detected.AddHours(2), "ic1", Now.AddHours(3));

        c.Invoking(x => x.UpdateDetails(x.Title, x.Summary, null, null, null, detected.AddHours(5), null, "ic1", Now.AddDays(1)))
            .Should().Throw<ArgumentException>().WithMessage("*regulator was notified*");

        var other = NewCase();
        other.ActionItems.Add(new ActionItem { CaseId = other.Id, Title = "Block", Status = ActionItemStatus.Done,
            CompletedAtUtc = other.DetectedAtUtc!.Value.AddHours(1), CreatedBy = "a1", CreatedAtUtc = Now });
        other.Invoking(x => x.UpdateDetails(x.Title, x.Summary, null, null, null, x.DetectedAtUtc!.Value.AddHours(2), null, "ic1", Now.AddDays(1)))
            .Should().Throw<ArgumentException>().WithMessage("*task was completed*");
    }

    [Fact]
    public void The_detected_time_cant_move_past_when_a_verdict_was_reached(/* BUG-436 */)
    {
        var c = NewCase();
        var detected = c.DetectedAtUtc!.Value;
        // Recorded a day later, but determined two hours after detection (BUG-414).
        c.VerdictChanges.Add(new EntityVerdictChange { CaseId = c.Id, EntityId = Guid.NewGuid(), EntityLabel = "evil.example",
            From = EntityDisposition.Unknown, To = EntityDisposition.Malicious, ChangedBy = "a1", ChangedAtUtc = Now.AddDays(1),
            EffectiveAtUtc = detected.AddHours(2) });

        c.Invoking(x => x.UpdateDetails(x.Title, x.Summary, null, null, null, detected.AddHours(3), null, "ic1", Now.AddDays(2)))
            .Should().Throw<ArgumentException>().WithMessage("*after a verdict was reached*");
        c.UpdateDetails(c.Title, c.Summary, null, null, null, detected.AddHours(1), null, "ic1", Now.AddDays(2));   // before it: fine
        c.DetectedAtUtc.Should().Be(detected.AddHours(1));
    }

    [Fact]
    public void Going_past_containment_without_it_needs_when_it_was_contained_or_why_it_wasnt_needed(/* BUG-165 */)
    {
        var c = NewCase();
        var detected = c.DetectedAtUtc!.Value;
        c.Invoking(x => x.ChangePhase(CasePhase.Eradication, null, "ic1", Now.AddHours(2)))
            .Should().Throw<ArgumentException>().WithMessage("*hasn't been through Containment*");
        c.Invoking(x => x.ChangePhase(CasePhase.Eradication, null, "ic1", Now.AddHours(2), containedAtUtc: Now.AddHours(3)))
            .Should().Throw<ArgumentException>();
        c.Phase.Should().NotBe(CasePhase.Eradication, "a refused move leaves the case as it was");

        c.ChangePhase(CasePhase.Eradication, null, "ic1", Now.AddHours(2), containedAtUtc: detected.AddHours(1));
        c.ContainedAtUtc.Should().Be(detected.AddHours(1));
        c.ContainmentNotNeededReason.Should().BeNull();

        var other = NewCase();
        other.ChangePhase(CasePhase.Recovery, null, "ic1", Now.AddHours(3), containmentNotNeededReason: "The link was never clicked");
        other.ContainmentNotNeededReason.Should().Be("The link was never clicked");
        other.ContainedAtUtc.Should().Be(Now.AddHours(3), "the containment clock stops at the decision");
        other.BuildCanonicalContent().Should().EndWith("|containmentnotneeded|The link was never clicked");
    }

    [Fact]
    public void Closing_straight_away_or_a_case_already_contained_needs_no_containment_decision(/* BUG-165 */)
    {
        var c = NewCase();
        c.ChangePhase(CasePhase.Closed, null, "ic1", Now.AddHours(1));
        c.Phase.Should().Be(CasePhase.Closed);

        var contained = NewCase();
        contained.ChangePhase(CasePhase.Containment, null, "ic1", Now.AddHours(1));
        contained.ChangePhase(CasePhase.Recovery, null, "ic1", Now.AddHours(2));
        contained.Invoking(x => x.ChangePhase(CasePhase.PostIncident, null, "ic1", Now.AddHours(3), containmentNotNeededReason: "x"))
            .Should().Throw<ArgumentException>().WithMessage("*only when a case goes past Containment*");
        NewCase().BuildCanonicalContent().Should().NotContain("containmentnotneeded", "a case without the decision hashes as before");
    }

    [Fact]
    public void Materiality_cant_be_decided_before_detection_nor_detection_moved_past_it(/* BUG-209 */)
    {
        var c = Case.Open(2026, 1, "Vendor", "Vendor incident", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "analyst1", Now);
        c.Invoking(x => x.RecordMateriality(MaterialityStatus.Material, "CISO", Now.AddHours(-1), "Harm likely", "a1", Now.AddDays(1)))
            .Should().Throw<ArgumentException>().WithMessage("*earlier than the detected time*");

        c.RecordMateriality(MaterialityStatus.Material, "CISO", Now.AddHours(5), "Harm likely", "a1", Now.AddDays(1));
        c.Invoking(x => x.UpdateDetails(x.Title, x.Summary, x.DetectionCaseId, x.DataTypesInvolved, x.ImpactedAssets,
                Now.AddHours(6), x.OccurredAtUtc, "a1", Now.AddDays(1)))
            .Should().Throw<ArgumentException>().WithMessage("*after materiality was decided*");
    }

    [Fact]
    public void Re_dating_a_move_that_skipped_containment_moves_the_decision_with_it(/* BUG-210 */)
    {
        var c = NewCase();
        c.ChangePhase(CasePhase.Eradication, null, "ic1", Now.AddHours(6), containmentNotNeededReason: "Never clicked");
        var move = c.StatusChanges.Single(s => s.To == CasePhase.Eradication);

        c.CorrectTransitionTime(TransitionKind.Phase, move.Id, Now.AddHours(1), "Logged late", "ic1", Now.AddHours(7));
        c.ContainedAtUtc.Should().Be(Now.AddHours(1), "the decision was made at that move");

        // And a resolution can't be re-dated before a containment that was needed.
        var d = NewCase();
        d.ChangePhase(CasePhase.Containment, null, "ic1", Now.AddHours(3));
        d.ChangePhase(CasePhase.Recovery, null, "ic1", Now.AddHours(5));
        var recovery = d.StatusChanges.Single(s => s.To == CasePhase.Recovery);
        d.Invoking(x => x.CorrectTransitionTime(TransitionKind.Phase, recovery.Id, Now.AddHours(2), "x", "ic1", Now.AddHours(6)))
            .Should().Throw<ArgumentException>();
        d.ResolvedAtUtc.Should().Be(Now.AddHours(5));
    }

    [Fact]
    public void Going_past_recovery_without_it_needs_when_it_was_resolved(/* BUG-208 */)
    {
        var c = NewCase();
        c.ChangePhase(CasePhase.Containment, null, "ic1", Now.AddHours(1));
        c.ChangePhase(CasePhase.Eradication, null, "ic1", Now.AddHours(2));
        c.SkipsRecovery(CasePhase.PostIncident).Should().BeTrue();
        c.Invoking(x => x.ChangePhase(CasePhase.PostIncident, null, "ic1", Now.AddHours(4)))
            .Should().Throw<ArgumentException>().WithMessage("*hasn't been through Recovery*");
        c.Invoking(x => x.ChangePhase(CasePhase.PostIncident, null, "ic1", Now.AddHours(4), resolvedAtUtc: Now.AddHours(5)))
            .Should().Throw<ArgumentException>();   // after the move (and in the future)
        c.Invoking(x => x.ChangePhase(CasePhase.PostIncident, null, "ic1", Now.AddHours(4), resolvedAtUtc: Now.AddMinutes(30)))
            .Should().Throw<ArgumentException>().WithMessage("*before it was contained*");

        c.ChangePhase(CasePhase.PostIncident, null, "ic1", Now.AddHours(4), resolvedAtUtc: Now.AddHours(3));
        c.ResolvedAtUtc.Should().Be(Now.AddHours(3), "the resolution clock stops when it was resolved");

        // Through Recovery, or closing straight away, there's nothing to say.
        var through = NewCase();
        through.ChangePhase(CasePhase.Recovery, null, "ic1", Now.AddHours(1), containmentNotNeededReason: "Nothing to contain");
        through.SkipsRecovery(CasePhase.PostIncident).Should().BeFalse();
        through.Invoking(x => x.ChangePhase(CasePhase.PostIncident, null, "ic1", Now.AddHours(2), resolvedAtUtc: Now.AddHours(1)))
            .Should().Throw<ArgumentException>().WithMessage("*only when a case goes past Recovery*");
        NewCase().SkipsRecovery(CasePhase.Closed).Should().BeFalse();
    }

    [Fact]
    public void Materiality_and_detection_are_compared_to_the_minute(/* BUG-231 */)
    {
        var c = NewCase();
        c.UpdateDetails(c.Title, c.Summary, null, null, null, Now.AddSeconds(-30), null, "ic1", Now.AddMinutes(1));   // 11:59:30
        c.Reclassify(Classification.Incident, "confirmed", "ic1", Now.AddMinutes(2));
        // The picker offers 11:59 for a detection at 11:59:30.
        c.RecordMateriality(MaterialityStatus.Material, "Committee", Now.AddMinutes(-1), "npi", "legal1", Now.AddHours(1));
        c.Materiality.DecidedOnUtc.Should().Be(Now.AddMinutes(-1));
    }

    [Theory]
    [InlineData(".")]
    [InlineData("[.]")]
    [InlineData("..")]
    public void A_domain_that_is_only_dots_is_refused(string value /* REV-18 */)
    {
        var c = NewCase();
        c.Invoking(x => x.AddEntity(EntityType.Domain, value, null, EntityDisposition.Unknown, null, null, "a1", Now))
            .Should().Throw<ArgumentException>().WithMessage("*empty once it's normalized*");
        var e = c.AddEntity(EntityType.Domain, "evil.example", null, EntityDisposition.Unknown, null, null, "a1", Now);
        c.Invoking(x => x.EditEntity(e.Id, EntityType.Domain, value, null, EntityDisposition.Unknown, null, null, "a1", Now))
            .Should().Throw<ArgumentException>();
        c.Entities.Should().ContainSingle().Which.Value.Should().Be("evil.example");
    }

    [Fact]
    public void A_change_dated_in_the_previous_changes_minute_is_kept_after_it(/* WF-52 */)
    {
        var c = NewCase();
        var triageAt = Now.AddMinutes(5).AddSeconds(37);   // recorded live, 12:05:37
        c.ChangePhase(CasePhase.Triage, null, "ic1", triageAt);

        // Ten minutes later, Containment is recorded as 12:05, what the picker offers.
        c.ChangePhase(CasePhase.Containment, null, "ic1", Now.AddMinutes(15), effectiveAtUtc: Now.AddMinutes(5));
        var contain = c.StatusChanges.Single(x => x.To == CasePhase.Containment);
        contain.EffectiveAt.Should().Be(triageAt.AddTicks(1), "held just after the previous change, so the two never tie");

        c.Invoking(x => x.ChangePhase(CasePhase.Eradication, null, "ic1", Now.AddMinutes(20), effectiveAtUtc: Now.AddMinutes(4)))
            .Should().Throw<ArgumentException>().WithMessage("*before the previous phase change*", "a minute earlier still is");

        // A correction into the neighbour's minute is held to it too.
        c.CorrectTransitionTime(TransitionKind.Phase, contain.Id, Now.AddMinutes(6), "typo", "ic1", Now.AddMinutes(21));
        c.CorrectTransitionTime(TransitionKind.Phase, contain.Id, Now.AddMinutes(5), "typo again", "ic1", Now.AddMinutes(22));
        c.StatusChanges.Single(x => x.Id == contain.Id).EffectiveAt.Should().Be(triageAt.AddTicks(1));
    }

    [Fact]
    public void Reopening_a_case_closed_before_containment_was_recorded_says_when_it_was_contained(/* WF-50 */)
    {
        var c = NewCase();
        c.ChangePhase(CasePhase.Triage, null, "ic1", Now.AddMinutes(10));
        c.ChangePhase(CasePhase.Eradication, null, "ic1", Now.AddMinutes(20), containedAtUtc: Now.AddMinutes(15));
        c.ChangePhase(CasePhase.Closed, "Concluded", "ic1", Now.AddHours(1), outcomeKey: "Confirmed");
        c.ContainedAtUtc = null;   // as a case closed before BUG-165 was left

        c.ReopenPhase().Should().Be(CasePhase.Eradication);
        c.SkipsContainment(c.ReopenPhase()).Should().BeTrue("the dialog asks");
        c.Invoking(x => x.Reopen("More to check", "ic1", Now.AddHours(2))).Should().Throw<ArgumentException>();

        c.Reopen("More to check", "ic1", Now.AddHours(2), containedAtUtc: Now.AddMinutes(15));
        c.Phase.Should().Be(CasePhase.Eradication);
        c.ContainedAtUtc.Should().Be(Now.AddMinutes(15));
    }

    [Fact]
    public void Every_not_before_detection_check_is_to_the_minute(/* REV-16 */)
    {
        var c = NewCase();
        c.UpdateDetails(c.Title, c.Summary, null, null, null, Now.AddSeconds(-30), null, "ic1", Now.AddMinutes(1));   // 11:59:30
        var minute = Now.AddMinutes(-1);   // 11:59, what the picker offers

        c.ChangePhase(CasePhase.Triage, null, "ic1", Now.AddMinutes(2), effectiveAtUtc: minute);
        c.ChangePhase(CasePhase.PostIncident, null, "ic1", Now.AddMinutes(3), containedAtUtc: minute, resolvedAtUtc: minute);
        c.MarkReported(minute, "lp1", Now.AddMinutes(4));
        var triage = c.StatusChanges.Single(x => x.To == CasePhase.Triage).Id;
        c.Invoking(x => x.CorrectTransitionTime(TransitionKind.Phase, triage, minute.AddMinutes(-1), "typo", "ic1", Now.AddMinutes(5)))
            .Should().Throw<ArgumentException>().WithMessage("*before the case was detected*", "a minute earlier still is");
    }

    [Fact]
    public void A_skip_move_cant_be_re_dated_before_the_times_it_stated(/* BUG-230 */)
    {
        var c = NewCase();
        c.ChangePhase(CasePhase.Containment, null, "ic1", Now.AddHours(1));
        c.ChangePhase(CasePhase.Eradication, null, "ic1", Now.AddHours(2));
        c.ChangePhase(CasePhase.PostIncident, null, "ic1", Now.AddHours(4), resolvedAtUtc: Now.AddHours(3));
        var move = c.StatusChanges.Single(s => s.To == CasePhase.PostIncident).Id;

        c.Invoking(x => x.CorrectTransitionTime(TransitionKind.Phase, move, Now.AddMinutes(150), "typo", "ic1", Now.AddHours(5)))
            .Should().Throw<ArgumentException>().WithMessage("*after the case was resolved*");
        c.CorrectTransitionTime(TransitionKind.Phase, move, Now.AddMinutes(200), "typo", "ic1", Now.AddHours(5));   // still after
    }

    [Fact]
    public void Coming_back_into_containment_takes_back_not_needed(/* BUG-229 */)
    {
        var c = NewCase();
        c.ChangePhase(CasePhase.Eradication, null, "ic1", Now.AddHours(1), containmentNotNeededReason: "Link never clicked");
        c.ContainmentNotNeededReason.Should().NotBeNull();

        c.ChangePhase(CasePhase.Containment, "it was clicked after all", "ic1", Now.AddHours(3));
        c.ContainmentNotNeededReason.Should().BeNull();
        c.ContainedAtUtc.Should().Be(Now.AddHours(3));
    }

    [Fact]
    public void Coming_back_into_containment_takes_back_a_resolution_recorded_on_the_way_past(/* REV-11 */)
    {
        var c = NewCase();
        c.ChangeSeverity(Severity.High, "worse", "ic1", Now.AddMinutes(30));
        c.ChangePhase(CasePhase.Recovery, null, "ic1", Now.AddHours(1), containmentNotNeededReason: "Link never clicked");
        c.ResolvedAtUtc.Should().Be(Now.AddHours(1));

        c.ChangePhase(CasePhase.Containment, "it was clicked after all", "ic1", Now.AddHours(3));
        c.ContainedAtUtc.Should().Be(Now.AddHours(3));
        c.ResolvedAtUtc.Should().BeNull("it can't have been resolved before it was contained");

        var severity = c.SeverityChanges.Single(x => x.From is not null).Id;
        c.CorrectTransitionTime(TransitionKind.Severity, severity, Now.AddMinutes(20), "logged late", "ic1", Now.AddHours(4));
        c.ChangePhase(CasePhase.Recovery, null, "ic1", Now.AddHours(5));
        c.ResolvedAtUtc.Should().Be(Now.AddHours(5));
    }

    [Fact]
    public void Leaving_closed_for_a_later_phase_asks_for_the_milestones_it_never_had(/* BUG-228 */)
    {
        var c = NewCase();
        c.ChangePhase(CasePhase.Triage, null, "ic1", Now.AddHours(1));
        c.ChangePhase(CasePhase.Closed, null, "ic1", Now.AddHours(2));   // closed from Triage: no contained or resolved time
        c.SkipsContainment(CasePhase.PostIncident).Should().BeTrue();
        c.SkipsRecovery(CasePhase.PostIncident).Should().BeTrue();
        c.SkipsContainment(CasePhase.Containment).Should().BeFalse();
        c.Invoking(x => x.ChangePhase(CasePhase.PostIncident, "new evidence", "ic1", Now.AddHours(3)))
            .Should().Throw<ArgumentException>();

        c.ChangePhase(CasePhase.PostIncident, "new evidence", "ic1", Now.AddHours(3),
            containedAtUtc: Now.AddMinutes(90), resolvedAtUtc: Now.AddMinutes(100));
        c.ContainedAtUtc.Should().Be(Now.AddMinutes(90));
        c.ResolvedAtUtc.Should().Be(Now.AddMinutes(100));
        c.ClosedAtUtc.Should().BeNull();
    }

    [Fact]
    public void The_detected_time_cant_move_past_a_complex_events_promotion(/* BUG-164 */)
    {
        var c = Case.Open(2026, 0, "Beaconing", "Odd beaconing", classification: null, Severity.Medium,
            CaseOrigin.InternalDetection, "a1", Now);
        var detected = c.DetectedAtUtc!.Value;
        c.Reclassify(Classification.Breach, "Data left", "ic1", Now.AddHours(4), effectiveAtUtc: detected.AddHours(1));

        c.Invoking(x => x.UpdateDetails(x.Title, x.Summary, null, null, null, detected.AddHours(2), null, "ic1", Now.AddDays(1)))
            .Should().Throw<ArgumentException>().WithMessage("*first reclassified*");
    }

    [Fact]
    public void An_entity_named_on_an_attack_step_is_not_removed(/* BUG-108 */)
    {
        var c = NewCase();
        var host = c.AddEntity(EntityType.Host, "FIN-WKS-07", null, EntityDisposition.Compromised, null, null, "a1", Now);
        var spare = c.AddEntity(EntityType.IpAddress, "203.0.113.9", null, EntityDisposition.Malicious, null, null, "a1", Now);
        c.TimelineEntries.Add(new TimelineEntry
        {
            CaseId = c.Id, Kind = TimelineKind.Event, Type = TimelineEntryType.Detection, OccurredAtUtc = Now,
            Description = "Beacon", TargetEntityId = host.Id, CreatedBy = "a1", CreatedAtUtc = Now
        });
        c.ActionItems.Add(new ActionItem { CaseId = c.Id, Title = "Block it", AboutRef = $"entity:{spare.Id}", CreatedBy = "a1", CreatedAtUtc = Now });

        c.Invoking(x => x.RemoveEntity(host.Id, "a1", Now)).Should().Throw<InvalidOperationException>().WithMessage("*attack step*");
        c.Entities.Should().Contain(host);

        c.RemoveEntity(spare.Id, "a1", Now);
        c.Entities.Should().NotContain(spare);
        c.ActionItems.Single().AboutRef.Should().BeNull("the task stays, no longer pointing at the removed entity");
    }

    [Fact]
    public void A_case_downgraded_after_a_determination_can_revise_it(/* BUG-59 */)
    {
        var c = NewCase();
        c.Reclassify(Classification.Incident, "confirmed", "ic1", Now);
        c.RecordMateriality(MaterialityStatus.Material, "Committee", Now, "npi exposed", "legal1", Now.AddHours(1));
        c.Reclassify(Classification.AdverseEvent, "turned out contained", "ic1", Now.AddHours(2));

        c.MaterialityApplies.Should().BeTrue("a Material call still runs the notification clock");
        c.RecordMateriality(MaterialityStatus.NotMaterial, "Committee", Now.AddHours(2), "no npi after all", "legal1", Now.AddHours(3));
        c.Materiality.Status.Should().Be(MaterialityStatus.NotMaterial);
    }

    [Fact]
    public void Case_numbers_use_the_gregorian_calendar_on_any_culture(/* BUG-59 */)
    {
        var was = System.Globalization.CultureInfo.CurrentCulture;
        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("th-TH");
            Case.FormatComplexEventNumber(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero), "X").Should().Be("CE-2026-08-08_X");
        }
        finally { System.Globalization.CultureInfo.CurrentCulture = was; }
    }

    [Fact]
    public void RecordMateriality_final_call_requires_decision_maker_date_and_rationale()
    {
        var c = NewCase();
        c.Reclassify(Classification.Incident, "confirmed", "ic1", Now);

        // Interim "under review" needs no provenance.
        c.RecordMateriality(MaterialityStatus.UnderReview, null, Now.AddMinutes(30), null, "legal1", Now.AddHours(1));
        c.Materiality.Status.Should().Be(MaterialityStatus.UnderReview);
        c.Materiality.DecidedOnUtc.Should().BeNull("only a call has a decision time (BUG-227)");

        // A material / not-material call must name who decided, when, and why.
        var missing = () => c.RecordMateriality(MaterialityStatus.Material, "  ", Now, "npi exfiltrated", "legal1", Now.AddHours(2));
        missing.Should().Throw<ArgumentException>();
        var noDate = () => c.RecordMateriality(MaterialityStatus.Material, "Disclosure Committee", null, "npi exfiltrated", "legal1", Now.AddHours(2));
        noDate.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void RecordMateriality_captures_the_off_app_decision_and_records_a_transition()
    {
        var c = NewCase();
        c.Reclassify(Classification.Breach, "npi confirmed", "ic1", Now);

        var decidedOn = Now.AddHours(3);
        c.RecordMateriality(MaterialityStatus.Material, "Disclosure Committee", decidedOn,
            "Reasonable likelihood of harm to NY residents.", "soc-analyst", Now.AddHours(4));

        c.Materiality.Status.Should().Be(MaterialityStatus.Material);
        c.Materiality.IsDetermined.Should().BeTrue();
        c.Materiality.DecisionMaker.Should().Be("Disclosure Committee");     // the external authority
        c.Materiality.DecidedOnUtc.Should().Be(decidedOn);
        c.Materiality.RecordedBy.Should().Be("soc-analyst");                 // the SOC recorder, kept distinct
        c.MaterialityChanges.Should().ContainSingle()
            .Which.Should().BeEquivalentTo(new { From = MaterialityStatus.Undetermined, To = MaterialityStatus.Material });
    }

    [Fact]
    public void RecordMateriality_rejects_a_future_decision_date()
    {
        var c = NewCase();
        c.Reclassify(Classification.Incident, "confirmed", "ic1", Now);
        var act = () => c.RecordMateriality(MaterialityStatus.Material, "GC", Now.AddDays(1), "why", "legal1", Now);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void UpdateDetails_edits_core_fields_and_requires_a_title()
    {
        var c = NewCase();
        var detected = Now.AddHours(-6);

        c.UpdateDetails("Refined title", "New summary", "SIEM-999", "PII", "web01, db02",
            detected, null, "analyst1", Now.AddHours(1));

        c.Title.Should().Be("Refined title");
        c.Summary.Should().Be("New summary");
        c.DetectionCaseId.Should().Be("SIEM-999");
        c.ImpactedAssets.Should().Be("web01, db02");

        var act = () => c.UpdateDetails("  ", null, null, null, null, detected, null, "analyst1", Now);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void UpdateDetails_rejects_moving_detection_past_a_milestone_already_reached()
    {
        var c = NewCase();
        var detected = Now.AddHours(-10);
        c.UpdateDetails("Title", null, null, null, null, detected, null, "analyst1", Now);
        c.ContainedAtUtc = Now.AddHours(-6);
        c.ResolvedAtUtc = Now.AddHours(-2);

        var afterContainment = () => c.UpdateDetails("Title", null, null, null, null, Now.AddHours(-5), null, "analyst1", Now);
        afterContainment.Should().Throw<ArgumentException>().WithMessage("*after the case was contained*");

        c.ContainedAtUtc = null;
        var afterResolution = () => c.UpdateDetails("Title", null, null, null, null, Now.AddHours(-1), null, "analyst1", Now);
        afterResolution.Should().Throw<ArgumentException>().WithMessage("*after the case was resolved*");

        // Exactly at the milestone is allowed (a zero-length response).
        c.UpdateDetails("Title", null, null, null, null, Now.AddHours(-2), null, "analyst1", Now);
        c.DetectedAtUtc.Should().Be(Now.AddHours(-2));
    }

    [Fact]
    public void UpdateDetails_rejects_moving_detection_past_closure_notification_or_a_phase_change()
    {
        // BUG-39: only containment and resolution were checked, so detection could land after closure (a negative MTTR)
        // or after the regulators were told.
        var c = NewCase();
        c.UpdateDetails("Title", null, null, null, null, Now.AddHours(-10), null, "analyst1", Now);
        c.ChangePhase(CasePhase.Triage, null, "analyst1", Now.AddHours(-8), effectiveAtUtc: Now.AddHours(-8));
        var afterPhase = () => c.UpdateDetails("Title", null, null, null, null, Now.AddHours(-7), null, "analyst1", Now);
        afterPhase.Should().Throw<ArgumentException>().WithMessage("*first changed phase*");

        c.ReportedAtUtc = Now.AddHours(-9);
        var afterReport = () => c.UpdateDetails("Title", null, null, null, null, Now.AddMinutes(-530), null, "analyst1", Now);
        afterReport.Should().Throw<ArgumentException>().WithMessage("*regulators were notified*");

        c.ReportedAtUtc = null;
        c.ClosedAtUtc = Now.AddHours(-9);
        var afterClose = () => c.UpdateDetails("Title", null, null, null, null, Now.AddMinutes(-530), null, "analyst1", Now);
        afterClose.Should().Throw<ArgumentException>().WithMessage("*after the case was closed*");
    }

    [Fact]
    public void UpdateDetails_rejects_initial_activity_more_than_ten_years_before_detection()
    {
        var c = NewCase();
        var detected = Now.AddHours(-1);

        var typo = () => c.UpdateDetails("Title", null, null, null, null, detected, new DateTimeOffset(1725, 6, 1, 0, 0, 0, TimeSpan.Zero), "analyst1", Now);
        typo.Should().Throw<ArgumentException>().WithMessage("*10 years before detection*");

        c.UpdateDetails("Title", null, null, null, null, detected, detected.AddYears(-10), "analyst1", Now);
        c.OccurredAtUtc.Should().Be(detected.AddYears(-10), "exactly ten years is allowed");

        // An older record already holding an implausible time can still have other details edited.
        c.OccurredAtUtc = new DateTimeOffset(1725, 6, 1, 0, 0, 0, TimeSpan.Zero);
        c.UpdateDetails("Renamed", null, null, null, null, detected, c.OccurredAtUtc, "analyst1", Now);
        c.Title.Should().Be("Renamed");
    }

    [Fact]
    public void UpdateDetails_still_saves_other_edits_on_a_record_that_already_breaks_the_milestone_rule()
    {
        var c = NewCase();
        c.DetectedAtUtc = Now.AddHours(-1);
        c.ContainedAtUtc = Now.AddHours(-3);   // older data, from before the rule

        c.UpdateDetails("Renamed", null, null, null, null, Now.AddHours(-1), null, "analyst1", Now);

        c.Title.Should().Be("Renamed");
    }

    [Fact]
    public void UpdateDetails_backdates_the_intake_timestamps_that_drive_the_sla_and_dwell_metrics()
    {
        var c = NewCase();
        c.DetectedAtUtc.Should().Be(Now); // defaults to case-creation time (E-34: often just tool-entry latency)

        // The analyst corrects "Detected" to the real detection time and captures when activity began.
        var occurred = Now.AddDays(-5);   // initial access
        var detected = Now.AddDays(-1);   // when the SOC actually caught it

        c.UpdateDetails("Beaconing on FS-07", null, null, null, null, detected, occurred, "analyst1", Now);

        c.DetectedAtUtc.Should().Be(detected);
        c.OccurredAtUtc.Should().Be(occurred);
    }

    [Fact]
    public void UpdateDetails_rejects_a_future_detection_or_activity_after_detection()
    {
        var c = NewCase();

        var future = () => c.UpdateDetails("t", null, null, null, null, Now.AddHours(1), null, "analyst1", Now);
        future.Should().Throw<ArgumentException>();

        var backwards = () => c.UpdateDetails("t", null, null, null, null, Now.AddHours(-1), Now, "analyst1", Now);
        backwards.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ChangeSeverity_updates_value_and_records_history()
    {
        var c = NewCase();

        c.ChangeSeverity(Severity.Critical, "escalating", "ic1", Now.AddHours(1));

        c.Severity.Should().Be(Severity.Critical);
        c.SeverityChanges.Should().HaveCount(2); // initial (Medium) + escalation
        c.SeverityChanges[^1].From.Should().Be(Severity.Medium);
        c.SeverityChanges[^1].To.Should().Be(Severity.Critical);
        c.SeverityChanges[^1].Reason.Should().Be("escalating");
    }

    [Fact]
    public void Assign_incident_commander_sets_the_commander_field()
    {
        var c = NewCase();

        c.Assign("ic1", "Ivy Commander", CaseAssignmentRole.IncidentCommander, "sysadmin", Now);

        c.Assignments.Should().ContainSingle();
        c.IncidentCommander.Should().Be("ic1");
    }

    [Fact]
    public void Assign_same_user_twice_updates_role_rather_than_duplicating()
    {
        var c = NewCase();

        c.Assign("analyst1", "Alex", CaseAssignmentRole.Analyst, "ic1", Now);
        c.Assign("analyst1", "Alex", CaseAssignmentRole.IncidentCommander, "ic1", Now.AddHours(1));

        c.Assignments.Should().ContainSingle().Which.Role.Should().Be(CaseAssignmentRole.IncidentCommander);
        c.IncidentCommander.Should().Be("analyst1");
    }

    [Fact]
    public void A_case_has_one_incident_commander()
    {
        var c = NewCase();
        c.Assign("ic1", "Ivy", CaseAssignmentRole.IncidentCommander, "sysadmin", Now);

        c.Assign("ic2", "Ian", CaseAssignmentRole.IncidentCommander, "sysadmin", Now.AddHours(1));
        c.IncidentCommander.Should().Be("ic2");
        c.Assignments.Single(a => a.UserId == "ic1").Role.Should().Be(CaseAssignmentRole.Analyst, "the previous commander stays on the team");

        c.Assign("ic2", "Ian", CaseAssignmentRole.Observer, "sysadmin", Now.AddHours(2));
        c.IncidentCommander.Should().BeNull("the commander moved to another role");
    }

    [Fact]
    public void Unassign_removes_the_user_and_clears_commander_when_applicable()
    {
        var c = NewCase();
        c.Assign("ic1", "Ivy", CaseAssignmentRole.IncidentCommander, "sysadmin", Now);

        c.Unassign("ic1", "sysadmin", Now.AddHours(1));

        c.Assignments.Should().BeEmpty();
        c.IncidentCommander.Should().BeNull();
    }

    [Fact]
    public void AddEntity_is_idempotent_by_type_and_value()
    {
        var c = NewCase();

        c.AddEntity(EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Unknown, null, null, "analyst1", Now);
        c.AddEntity(EntityType.IpAddress, "203.0.113.66", "Attacker", EntityDisposition.Malicious, null, "SIEM", "analyst1", Now.AddHours(1));

        c.Entities.Should().ContainSingle();
        var e = c.Entities[0];
        e.Disposition.Should().Be(EntityDisposition.Malicious); // an Unknown verdict takes the first real one
        e.Label.Should().Be("Attacker");                          // blanks are filled
        e.Source.Should().Be("SIEM");
    }

    [Fact]
    public void AddEntity_again_never_overwrites_a_recorded_verdict_or_detail()
    {
        // HR-04: re-adding an indicator (form, paste, "+ New IOC…") silently turned "Malicious · Tor exit node" into
        // "Suspicious · —". A re-add now keeps what the case recorded; changing it is an edit.
        var c = NewCase();
        c.AddEntity(EntityType.IpAddress, "185.220.101.47", "Tor exit node", EntityDisposition.Malicious,
            "Source of the unauthorized sign-in", "Entra ID", "analyst1", Now);
        var stamp = c.Entities[0].ModifiedAtUtc;

        var again = c.AddEntity(EntityType.IpAddress, "185.220.101[.]47", null, EntityDisposition.Suspicious,
            null, "Proxy log", "analyst2", Now.AddHours(2));

        c.Entities.Should().ContainSingle();
        again.Disposition.Should().Be(EntityDisposition.Malicious);
        again.Label.Should().Be("Tor exit node");
        again.Description.Should().Be("Source of the unauthorized sign-in");
        again.Source.Should().Be("Entra ID");
        again.ModifiedAtUtc.Should().Be(stamp, "nothing changed, so nothing is recorded as edited");
    }

    [Fact]
    public void The_outcome_is_hashed_only_when_recorded_and_cleared_on_reopen()
    {
        // HR-01: cases closed before outcomes existed keep their exact hash.
        var c = NewCase();
        var before = c.BuildCanonicalContent();
        before.Should().NotContain("|outcome|");

        c.ChangePhase(CasePhase.Closed, "Concluded", "ic1", Now.AddHours(1), outcomeKey: "Confirmed");
        c.BuildCanonicalContent().Should().EndWith("|outcome|Confirmed");
        c.StatusChanges.Last().OutcomeKey.Should().Be("Confirmed");

        c.Reopen("More activity", "ic1", Now.AddHours(2));
        c.OutcomeKey.Should().BeNull();
        c.BuildCanonicalContent().Should().NotContain("|outcome|");
        var act = () => c.ChangePhase(CasePhase.Eradication, null, "ic1", Now.AddHours(3), outcomeKey: "Confirmed");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void A_reassessed_verdict_is_recorded_with_why_and_projected_as_a_finding()
    {
        // HR-05: the findings history. Adding an entity with a verdict isn't a re-assessment; changing one is.
        var c = NewCase();
        var acct = c.AddEntity(EntityType.Account, "j.morales", "Jordan Morales", EntityDisposition.Unknown, null, null, "an1", Now);
        c.AddEntity(EntityType.IpAddress, "185.220.101.47", null, EntityDisposition.Malicious, null, null, "an1", Now);
        c.VerdictChanges.Should().BeEmpty();

        c.EditEntity(acct.Id, EntityType.Account, "j.morales", "Jordan Morales (Finance AP)", EntityDisposition.Compromised,
            null, null, "an1", Now.AddHours(1), reason: "Unauthorized Tor sign-in after MFA fatigue");
        c.EditEntity(acct.Id, EntityType.Account, "j.morales", "Renamed", EntityDisposition.Compromised,
            "detail only", null, "an1", Now.AddHours(2));   // no verdict change: nothing recorded
        c.AddEntity(EntityType.Host, "FIN-LT-0442", null, EntityDisposition.Unknown, null, null, "an1", Now.AddHours(3));
        c.AddEntity(EntityType.Host, "FIN-LT-0442", null, EntityDisposition.Benign, null, null, "an2", Now.AddHours(4));

        c.VerdictChanges.Should().HaveCount(2);
        var first = c.VerdictChanges[0];
        first.EntityLabel.Should().Be("Jordan Morales", "it reads as the entity did when assessed");
        (first.From, first.To, first.Reason).Should().Be((EntityDisposition.Unknown, EntityDisposition.Compromised,
            "Unauthorized Tor sign-in after MFA fatigue"));
        c.VerdictChanges[1].Should().Match<EntityVerdictChange>(v => v.EntityLabel == "FIN-LT-0442" && v.To == EntityDisposition.Benign
            && v.Reason == "Set when added again" && v.ChangedBy == "an2");   // WF-29: never reasonless

        var milestones = IncidentManager.Application.Cases.CaseMilestones.Project(c,
                new IncidentManager.Application.Cases.MilestoneLabels(x => "", s => "", p => "", m => ""))
            .Where(m => m.Kind == IncidentManager.Application.Cases.MilestoneKind.Verdict).ToList();
        milestones.Select(m => m.Title).Should().Equal("Jordan Morales assessed Compromised", "FIN-LT-0442 assessed Benign");
        milestones[0].Detail.Should().Be("Unauthorized Tor sign-in after MFA fatigue");
    }

    [Fact]
    public void Changes_in_the_working_assessment_are_projected_and_the_closing_conclusion_is_left_to_the_close()
    {
        // HR-06: what the team believed, in sequence. Versions that don't change the assessment add nothing.
        var c = NewCase();
        c.ReviseBrief("Impossible travel", null, null, null, null, "an1", Now);
        c.ReviseBrief("Impossible travel", "Probably MFA fatigue", null, null, null, "an1", Now.AddHours(1));
        c.ReviseBrief("Impossible travel", "Probably MFA fatigue", "- Tor sign-in", null, null, "an1", Now.AddHours(2));
        c.ReviseBrief("Impossible travel", "Takeover; inbox rule points to payment fraud", "- Tor sign-in", null, null, "an2", Now.AddHours(3));
        c.ReviseBrief("What happened", "Concluded: takeover, no payment", null, null, null, "an1", Now.AddHours(5));
        c.ChangePhase(CasePhase.Closed, "Concluded: takeover, no payment", "an1", Now.AddHours(5), outcomeKey: "Confirmed");

        var ms = IncidentManager.Application.Cases.CaseMilestones.Project(c,
                new IncidentManager.Application.Cases.MilestoneLabels(x => "", s => "", p => "", m => ""))
            .Where(m => m.Kind == IncidentManager.Application.Cases.MilestoneKind.Assessment).ToList();

        ms.Select(m => (m.Title, m.Detail, m.Actor)).Should().Equal(
            ("Working assessment recorded (brief v2)", "Probably MFA fatigue", "an1"),
            ("Assessment revised (brief v4)", "Takeover; inbox rule points to payment fraud", "an2"));
    }

    [Fact]
    public void A_case_filed_late_starts_at_detection_and_passed_gates_fold_into_their_transition()
    {
        // HR-07: the story starts when the activity did; record-keeping doesn't crowd it.
        var c = NewCase();   // opened at Now
        c.UpdateDetails(c.Title, null, "XSIAM-88231", null, null, Now.AddDays(-3), Now.AddDays(-3).AddMinutes(-21), "an1", Now);
        c.RecordGatePassage(StageGateTrigger.EscalateToIncident, false, null, "Takeover confirmed", "[MET] x", "ic1", Now.AddMinutes(10));
        c.Reclassify(Classification.Incident, "Takeover confirmed", "ic1", Now.AddMinutes(10), Now.AddDays(-3).AddHours(1));
        c.RecordGatePassage(StageGateTrigger.CloseCase, true, "Report pending", "Closed", "[UNMET(OVERRIDDEN)] y", "ic1", Now.AddMinutes(20));
        c.ChangePhase(CasePhase.Closed, "Closed", "ic1", Now.AddMinutes(20), Now.AddDays(-1), outcomeKey: "Confirmed");

        var ms = IncidentManager.Application.Cases.CaseMilestones.Project(c,
            new IncidentManager.Application.Cases.MilestoneLabels(x => x?.ToString() ?? "Complex Event", s => s.ToString(), p => p.ToString(), m => ""));

        var opened = ms.Single(m => m.Kind == IncidentManager.Application.Cases.MilestoneKind.Opened);
        opened.AtUtc.Should().Be(Now.AddDays(-3));
        opened.RecordedAtUtc.Should().Be(Now);
        opened.Title.Should().StartWith("Detected (XSIAM-88231); case opened as");
        var began = ms.Single(m => m.Kind == IncidentManager.Application.Cases.MilestoneKind.ActivityBegan);
        (began.AtUtc, began.Detail).Should().Be((Now.AddDays(-3).AddMinutes(-21), "21 min before detection"));

        ms.Single(m => m.Kind == IncidentManager.Application.Cases.MilestoneKind.Classification).Note
            .Should().Be("Incident escalation gate passed");
        var gate = ms.Single(m => m.Kind == IncidentManager.Application.Cases.MilestoneKind.Gate);   // the override stays a row
        gate.Flagged.Should().BeTrue();
        gate.AtUtc.Should().Be(Now.AddDays(-1), "at the close it guarded, not when it was recorded");
        gate.RecordedAtUtc.Should().Be(Now.AddMinutes(20));
        ms.Select(m => m.Kind).Should().ContainInOrder(
            IncidentManager.Application.Cases.MilestoneKind.ActivityBegan, IncidentManager.Application.Cases.MilestoneKind.Opened);
    }

    [Fact]
    public void Every_gate_a_climb_passes_folds_into_its_transition_in_climb_order(/* BUG-492 */)
    {
        // A Complex Event raised straight to Breach passes a gate per rung, in one save (recorded in any order).
        var c = Case.Open(2026, 0, "Beaconing", "Odd beaconing", classification: null, Severity.Medium,
            CaseOrigin.InternalDetection, "a1", Now);
        var at = Now.AddHours(1);
        c.RecordGatePassage(StageGateTrigger.EscalateToBreach, false, null, "Data left", "[MET] z", "ic1", at);
        c.RecordGatePassage(StageGateTrigger.PromoteToAdverseEvent, false, null, "Data left", "[MET] x", "ic1", at);
        c.RecordGatePassage(StageGateTrigger.EscalateToIncident, false, null, "Data left", "[MET] y", "ic1", at);
        c.Reclassify(Classification.Breach, "Data left", "ic1", at);
        var labels = new IncidentManager.Application.Cases.MilestoneLabels(x => x?.ToString() ?? "Complex Event", s => s.ToString(), p => p.ToString(), m => "");

        var ms = IncidentManager.Application.Cases.CaseMilestones.Project(c, labels);

        ms.Single(m => m.Kind == IncidentManager.Application.Cases.MilestoneKind.Classification).Note
            .Should().Be("Promotion, Incident escalation and Breach escalation gates passed");
        ms.Should().NotContain(m => m.Kind == IncidentManager.Application.Cases.MilestoneKind.Gate);

        // Two rungs: "and"; an overridden rung stays its own flagged row and leaves the passed one's note alone.
        var d = Case.Open(2026, 0, "Beaconing", "Odd beaconing", classification: null, Severity.Medium,
            CaseOrigin.InternalDetection, "a1", Now);
        d.RecordGatePassage(StageGateTrigger.PromoteToAdverseEvent, false, null, "Takeover", "[MET] x", "ic1", at);
        d.RecordGatePassage(StageGateTrigger.EscalateToIncident, false, null, "Takeover", "[MET] y", "ic1", at);
        d.Reclassify(Classification.Incident, "Takeover", "ic1", at);
        CaseMilestonesNote(d).Should().Be("Promotion and Incident escalation gates passed");

        var e = Case.Open(2026, 0, "Beaconing", "Odd beaconing", classification: null, Severity.Medium,
            CaseOrigin.InternalDetection, "a1", Now);
        e.RecordGatePassage(StageGateTrigger.PromoteToAdverseEvent, false, null, "Takeover", "[MET] x", "ic1", at);
        e.RecordGatePassage(StageGateTrigger.EscalateToIncident, true, "Lead on leave", "Takeover", "[UNMET(OVERRIDDEN)] y", "ic1", at);
        e.Reclassify(Classification.Incident, "Takeover", "ic1", at);
        CaseMilestonesNote(e).Should().Be("Promotion gate passed");
        IncidentManager.Application.Cases.CaseMilestones.Project(e, labels)
            .Should().ContainSingle(m => m.Kind == IncidentManager.Application.Cases.MilestoneKind.Gate && m.Flagged);

        string? CaseMilestonesNote(Case x) => IncidentManager.Application.Cases.CaseMilestones.Project(x, labels)
            .Single(m => m.Kind == IncidentManager.Application.Cases.MilestoneKind.Classification).Note;
    }

    [Fact]
    public void Gates_passed_when_a_case_was_filed_never_fold_into_a_later_escalation(/* BUG-504 */)
    {
        // Filed as an Incident (the creation save passes Promotion and Incident escalation), escalated 30 s later.
        var c = Case.Open(2026, 7, "Takeover", "Mailbox takeover", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "a1", Now);
        c.RecordGatePassage(StageGateTrigger.PromoteToAdverseEvent, false, null, "Filed: takeover", "[MET] x", "a1", Now);
        c.RecordGatePassage(StageGateTrigger.EscalateToIncident, false, null, "Filed: takeover", "[MET] y", "a1", Now.AddMilliseconds(40));
        var at = Now.AddSeconds(30);
        c.RecordGatePassage(StageGateTrigger.EscalateToBreach, false, null, "Data left", "[MET] z", "ic1", at);
        c.Reclassify(Classification.Breach, "Data left", "ic1", at);
        var labels = new IncidentManager.Application.Cases.MilestoneLabels(x => x?.ToString() ?? "Complex Event", s => s.ToString(), p => p.ToString(), m => "");

        var ms = IncidentManager.Application.Cases.CaseMilestones.Project(c, labels);

        ms.Single(m => m.Kind == IncidentManager.Application.Cases.MilestoneKind.Classification).Note
            .Should().Be("Breach escalation gate passed");
        ms.Where(m => m.Kind == IncidentManager.Application.Cases.MilestoneKind.Gate).Select(m => (m.Title, m.Detail))
            .Should().Equal(("Promotion gate passed", "Filed: takeover"), ("Incident escalation gate passed", "Filed: takeover"));

        // Lowered and raised again: that second Incident passage guards the re-escalation, so it folds.
        c.Reclassify(Classification.AdverseEvent, "Not a breach after all", "ic1", Now.AddMinutes(5));
        c.RecordGatePassage(StageGateTrigger.EscalateToIncident, false, null, "Takeover again", "[MET] y", "ic1", Now.AddMinutes(9));
        c.Reclassify(Classification.Incident, "Takeover again", "ic1", Now.AddMinutes(9));
        ms = IncidentManager.Application.Cases.CaseMilestones.Project(c, labels);
        ms.Where(m => m.Kind == IncidentManager.Application.Cases.MilestoneKind.Classification).Select(m => m.Note)
            .Should().Equal("Breach escalation gate passed", null, "Incident escalation gate passed");
        ms.Count(m => m.Kind == IncidentManager.Application.Cases.MilestoneKind.Gate).Should().Be(2);
    }

    [Fact]
    public void AddEntity_again_does_not_downgrade_benign_either()
    {
        var c = NewCase();
        c.AddEntity(EntityType.Host, "FIN-LT-0442", null, EntityDisposition.Benign, null, null, "analyst1", Now);

        c.AddEntity(EntityType.Host, "fin-lt-0442", "Laptop", EntityDisposition.Suspicious, null, null, "analyst1", Now.AddHours(1));

        c.Entities.Should().ContainSingle();
        c.Entities[0].Disposition.Should().Be(EntityDisposition.Benign);
        c.Entities[0].Label.Should().Be("Laptop");
        c.FindEntity(EntityType.Host, "FIN-LT-0442").Should().BeSameAs(c.Entities[0]);
        c.FindEntity(EntityType.Account, "FIN-LT-0442").Should().BeNull();
    }

    [Fact]
    public void AddEntity_refangs_on_entry_so_defanged_and_live_values_dedup()
    {
        var c = NewCase();

        // An analyst pastes a defanged IOC, then someone else adds the live form (E-19).
        var first = c.AddEntity(EntityType.Url, "hxxp://evil[.]com/login", null,
            EntityDisposition.Unknown, null, null, "analyst1", Now);
        var second = c.AddEntity(EntityType.Url, "http://evil.com/login", "Phishing kit",
            EntityDisposition.Malicious, null, "SIEM", "analyst2", Now.AddHours(1));

        c.Entities.Should().ContainSingle("the defanged and live values normalize to the same observable");
        second.Should().BeSameAs(first);
        first.Value.Should().Be("http://evil.com/login"); // stored canonical, ready for E-08/E-13
        first.Disposition.Should().Be(EntityDisposition.Malicious);
    }

    [Fact]
    public void AddEntity_leaves_non_network_values_untouched()
    {
        var c = NewCase();

        // A registry key with literal brackets must not be refanged — only trimmed.
        var e = c.AddEntity(EntityType.RegistryKey, @"  HKLM\Software\X[.]Y  ", null,
            EntityDisposition.Suspicious, null, null, "analyst1", Now);

        e.Value.Should().Be(@"HKLM\Software\X[.]Y");
    }

    [Fact]
    public void SetReportProfile_sets_clears_and_stays_out_of_the_canonical()
    {
        var c = NewCase();
        var before = c.BuildCanonicalContent();

        c.SetReportProfile(Guid.NewGuid(), "analyst1", Now.AddHours(1));
        c.ReportProfileId.Should().NotBeNull();
        c.ModifiedBy.Should().Be("analyst1");
        // A reporting preference — must not re-baseline the tamper-evident row hash.
        c.BuildCanonicalContent().Should().Be(before);

        c.SetReportProfile(null, "analyst1", Now.AddHours(2));
        c.ReportProfileId.Should().BeNull();
    }

    [Fact]
    public void LinkEntities_creates_a_directed_relationship_and_dedupes()
    {
        var c = NewCase();
        var a = c.AddEntity(EntityType.Account, "jdoe", null, EntityDisposition.Unknown, null, null, "analyst1", Now);
        var h = c.AddEntity(EntityType.Host, "WKS-07", null, EntityDisposition.Benign, null, null, "analyst1", Now);

        c.LinkEntities(a.Id, h.Id, EntityRelationshipType.LoggedInTo, null, "analyst1", Now);
        c.LinkEntities(a.Id, h.Id, EntityRelationshipType.LoggedInTo, "dupe", "analyst1", Now.AddHours(1));

        c.EntityRelationships.Should().ContainSingle();
        c.EntityRelationships[0].SourceEntityId.Should().Be(a.Id);
        c.EntityRelationships[0].TargetEntityId.Should().Be(h.Id);
    }

    [Fact]
    public void LinkEntities_rejects_self_reference()
    {
        var c = NewCase();
        var a = c.AddEntity(EntityType.Account, "jdoe", null, EntityDisposition.Unknown, null, null, "analyst1", Now);

        var act = () => c.LinkEntities(a.Id, a.Id, EntityRelationshipType.RelatedTo, null, "analyst1", Now);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void RemoveEntity_also_removes_relationships_that_reference_it()
    {
        var c = NewCase();
        var a = c.AddEntity(EntityType.Account, "jdoe", null, EntityDisposition.Unknown, null, null, "analyst1", Now);
        var h = c.AddEntity(EntityType.Host, "WKS-07", null, EntityDisposition.Benign, null, null, "analyst1", Now);
        c.LinkEntities(a.Id, h.Id, EntityRelationshipType.LoggedInTo, null, "analyst1", Now);

        c.RemoveEntity(h.Id, "analyst1", Now.AddHours(1));

        c.Entities.Should().ContainSingle().Which.Id.Should().Be(a.Id);
        c.EntityRelationships.Should().BeEmpty();
    }

    [Fact]
    public void Open_as_complex_event_has_no_classification_and_records_no_initial_change()
    {
        // A Complex Event is filed off the ladder (pre-triage intake) — no classification yet, so no
        // initial classification transition is recorded (status/severity history still seed).
        var c = Case.Open(2026, 2, "Odd Beaconing", "Unexplained outbound beaconing",
            classification: null, Severity.Low, CaseOrigin.InternalDetection, "analyst1", Now);

        c.Classification.Should().BeNull();
        c.ClassificationChanges.Should().BeEmpty();
        c.StatusChanges.Should().ContainSingle().Which.To.Should().Be(CasePhase.New);
    }

    [Fact]
    public void Promoting_a_complex_event_records_a_transition_from_null()
    {
        var c = Case.Open(2026, 2, "Odd Beaconing", "Unexplained outbound beaconing",
            classification: null, Severity.Low, CaseOrigin.InternalDetection, "analyst1", Now);

        c.Reclassify(Classification.AdverseEvent, "Triaged — confirmed adverse event", "ic1", Now.AddHours(1));

        c.Classification.Should().Be(Classification.AdverseEvent);
        c.ClassificationChanges.Should().ContainSingle();
        c.ClassificationChanges[^1].From.Should().BeNull("promotion is the case's first classification");
        c.ClassificationChanges[^1].To.Should().Be(Classification.AdverseEvent);
    }

    [Fact]
    public void Canonical_keeps_the_integer_slot_for_a_classified_case_and_blanks_it_for_intake()
    {
        // Guards the tamper-evidence guarantee: existing (classified) rows re-hash byte-identically —
        // the classification segment stays the enum's integer — while a Complex Event blanks that slot.
        var classified = NewCase(); // AdverseEvent == 1
        classified.BuildCanonicalContent().Split('|')[2].Should().Be("1");

        var intake = Case.Open(2026, 2, "Odd Beaconing", "Unexplained outbound beaconing",
            classification: null, Severity.Low, CaseOrigin.InternalDetection, "analyst1", Now);
        intake.BuildCanonicalContent().Split('|')[2].Should().BeEmpty();
    }

    [Theory]
    [InlineData("Phishing Wave", "Phishing_Wave")]
    [InlineData("  Ransomware!! @ HQ  ", "Ransomware_HQ")]
    [InlineData("VPN-Compromise_2026", "VPN_Compromise_2026")]
    [InlineData("///", "Case")]
    public void Slug_produces_identifier_safe_names(string input, string expected)
        => Case.Slug(input).Should().Be(expected);
}
