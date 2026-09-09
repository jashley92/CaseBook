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
    public void ReferToLegal_captures_referral_without_deadlines()
    {
        var c = NewCase();

        c.ReferToLegal("ic1", "legal@example.com", "NY resident NPI potentially involved", Now.AddHours(1));

        c.LegalReferral.IsReferred.Should().BeTrue();
        c.LegalReferral.ReferredToContact.Should().Be("legal@example.com");
        c.LegalReferral.ReferredAtUtc.Should().Be(Now.AddHours(1));
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

        c.AddEntity(EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Suspicious, null, null, "analyst1", Now);
        c.AddEntity(EntityType.IpAddress, "203.0.113.66", "Attacker", EntityDisposition.Malicious, null, "SIEM", "analyst1", Now.AddHours(1));

        c.Entities.Should().ContainSingle();
        var e = c.Entities[0];
        e.Disposition.Should().Be(EntityDisposition.Malicious); // updated in place
        e.Label.Should().Be("Attacker");
    }

    [Fact]
    public void AddEntity_refangs_on_entry_so_defanged_and_live_values_dedup()
    {
        var c = NewCase();

        // An analyst pastes a defanged IOC, then someone else adds the live form (E-19).
        var first = c.AddEntity(EntityType.Url, "hxxp://evil[.]com/login", null,
            EntityDisposition.Suspicious, null, null, "analyst1", Now);
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
