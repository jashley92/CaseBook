using System.IO.Compression;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Reporting;
using IncidentManager.Infrastructure.Reporting;
using Xunit;

namespace IncidentManager.UnitTests;

public class ReportLayoutTests
{
    [Fact]
    public void Blank_layout_enables_every_section_except_analyst_notes_in_enum_order()
    {
        // INV-19: the case brief is off by default too.
        var expected = System.Enum.GetValues<ReportSection>().Where(s => s is not (ReportSection.AnalystNotes or ReportSection.CaseBrief));
        ReportLayout.Resolve(null).Should().Equal(expected);
        ReportLayout.Resolve("").Should().Equal(expected);
    }

    [Fact]
    public void A_layout_saved_before_analyst_notes_existed_keeps_notes_out()
    {
        // An upgrade must never start printing notes in reports that didn't have them.
        ReportLayout.Resolve("Summary,Outcome,Appendix").Should().NotContain(ReportSection.AnalystNotes);
        ReportLayout.Parse("Summary").Should().Contain(new ReportSectionState(ReportSection.AnalystNotes, false));
    }

    [Fact]
    public void Analyst_notes_print_only_when_the_layout_turns_them_on()
    {
        ReportLayout.Resolve("Summary,AnalystNotes").Should().Contain(ReportSection.AnalystNotes);

        CaseReportModel Model(params ReportSection[] sections) => new()
        {
            Sections = sections,
            CaseNumber = "2026-09", Title = "Notes test", Classification = "Incident", Phase = "Triage",
            Severity = "Low", Origin = "Internal detection", Summary = "s",
            Notes = [new ReportNoteItem(System.DateTimeOffset.UnixEpoch, "Dana", "NOTE_MARKER")],
            GeneratedBy = "tester", GeneratedAtUtc = System.DateTimeOffset.UnixEpoch, ContentHash = new string('a', 64),
        };

        var off = WordXml(new ReportGenerator().GenerateWord(Model(ReportSection.Summary, ReportSection.Appendix)));
        off.Should().NotContain("NOTE_MARKER", "notes are no longer part of the appendix");
        var on = WordXml(new ReportGenerator().GenerateWord(Model(ReportSection.Summary, ReportSection.AnalystNotes)));
        on.Should().Contain("Analyst Notes").And.Contain("NOTE_MARKER");
    }

    [Fact]
    public void Control_characters_in_case_text_dont_break_the_report()
    {
        // BUG-42: XML 1.0 can't hold most control characters; one from an import (a pasted terminal bell, say) made every
        // later report for the case fail. They're dropped; the rest of the text prints.
        var model = new CaseReportModel
        {
            Sections = [ReportSection.Summary, ReportSection.AnalystNotes],
            CaseNumber = "2026-09", Title = "Bell\u0007 in the title", Classification = "Incident", Phase = "Triage",
            Severity = "Low", Origin = "Internal detection", Summary = "s",
            Notes = [new ReportNoteItem(System.DateTimeOffset.UnixEpoch, "Dana", "Note\u000B\u0000with a vertical tab\u001B")],
            GeneratedBy = "tester", GeneratedAtUtc = System.DateTimeOffset.UnixEpoch, ContentHash = new string('a', 64),
        };

        var xml = WordXml(new ReportGenerator().GenerateWord(model));
        xml.Should().Contain("Bell in the title").And.Contain("Notewith a vertical tab");
    }

    [Fact]
    public void The_evidence_index_says_how_a_file_was_collected_when_one_does(/* CAP-08 */)
    {
        var at = new System.DateTimeOffset(2026, 10, 1, 9, 30, 0, System.TimeSpan.Zero);
        CaseReportModel Model(params ReportEvidenceItem[] evidence) => new()
        {
            Sections = [ReportSection.Appendix], CaseNumber = "2026-09", Title = "t", Classification = "Incident", Phase = "Triage",
            Severity = "Low", Origin = "Internal detection", Summary = "s", Evidence = evidence,
            GeneratedBy = "tester", GeneratedAtUtc = System.DateTimeOffset.UnixEpoch, ContentHash = new string('a', 64),
        };
        var collected = new ReportEvidenceItem("mail.eml", 10, new string('b', 64), at.AddHours(5), "Dana", at, "mx01", "Messaging team");
        var plain = new ReportEvidenceItem("plain.txt", 5, new string('c', 64), at, "Dana");

        WordXml(new ReportGenerator().GenerateWord(Model(collected, plain)))
            .Should().Contain("Collected").And.Contain("2026-10-01 09:30 UTC, from mx01 by Messaging team");
        WordXml(new ReportGenerator().GenerateWord(Model(plain))).Should().NotContain("Collected", "an index without a collection reads as before");

        // The Word template fields, each empty when not recorded.
        foreach (var f in new[] { "evidence.collected", "evidence.collected_from", "evidence.collected_by" })
            ReportTemplateFields.CollectionFor(f).Should().Be("evidence", f);
        var items = ReportTemplateFields.Items(Model(collected, plain), "evidence");
        (items[0]("evidence.collected"), items[0]("evidence.collected_from"), items[0]("evidence.collected_by"))
            .Should().Be(("2026-10-01 09:30 UTC", "mx01", "Messaging team"));
        (items[1]("evidence.collected"), items[1]("evidence.collected_from"), items[1]("evidence.collected_by")).Should().Be(("", "", ""));
    }

    [Fact]
    public void A_bang_prefix_hides_a_section_but_keeps_its_position()
    {
        var parsed = ReportLayout.Parse("Summary,!BusinessImpact,EventTimeline");
        parsed[0].Should().Be(new ReportSectionState(ReportSection.Summary, true));
        parsed[1].Should().Be(new ReportSectionState(ReportSection.BusinessImpact, false));
        parsed[2].Should().Be(new ReportSectionState(ReportSection.EventTimeline, true));

        ReportLayout.Resolve("Summary,!BusinessImpact,EventTimeline")
            .Should().NotContain(ReportSection.BusinessImpact)
            .And.ContainInOrder(ReportSection.Summary, ReportSection.EventTimeline);
    }

    [Fact]
    public void Custom_order_is_preserved()
    {
        ReportLayout.Resolve("Outcome,Summary,Appendix")
            .Should().StartWith(ReportSection.Outcome)
            .And.ContainInOrder(ReportSection.Outcome, ReportSection.Summary, ReportSection.Appendix);
    }

    [Fact]
    public void Sections_missing_from_a_stored_layout_are_appended_enabled_forward_compat()
    {
        // Only two sections stored (as if saved before others existed): the rest come back enabled, except
        // Analyst Notes, which stays off until a layout turns it on.
        var expected = System.Enum.GetValues<ReportSection>().Where(s => s is not (ReportSection.AnalystNotes or ReportSection.CaseBrief)).ToList();
        var resolved = ReportLayout.Resolve("Outcome,Summary");
        resolved.Should().StartWith(ReportSection.Outcome);
        resolved.Should().Contain(expected); // none dropped
        resolved.Count.Should().Be(expected.Count);
    }

    [Fact]
    public void The_case_brief_stays_out_of_existing_layouts_and_prints_only_when_turned_on()
    {
        // INV-19: an upgrade must never start printing the brief (working understanding) in existing reports.
        ReportLayout.Resolve("Summary,Outcome,Appendix").Should().NotContain(ReportSection.CaseBrief);
        ReportLayout.Resolve("Summary,CaseBrief,Outcome").Should().Contain(ReportSection.CaseBrief);
    }

    [Fact]
    public void Unknown_and_duplicate_tokens_are_ignored()
    {
        var resolved = ReportLayout.Resolve("Summary,Bogus,Summary,Appendix");
        resolved.Count(s => s == ReportSection.Summary).Should().Be(1);
        resolved.Should().Contain(ReportSection.Appendix);
    }

    [Fact]
    public void Reports_use_Aptos_with_Aptos_Display_headings()
    {
        var model = new CaseReportModel
        {
            Sections = new[] { ReportSection.Summary },
            CaseNumber = "2026-09", Title = "Font test", Classification = "Incident", Phase = "Triage",
            Severity = "Low", Origin = "Internal detection", Summary = "s",
            GeneratedBy = "tester", GeneratedAtUtc = System.DateTimeOffset.UnixEpoch, ContentHash = new string('a', 64),
        };
        using var zip = new ZipArchive(new MemoryStream(new ReportGenerator().GenerateWord(model)), ZipArchiveMode.Read);
        using var styles = new StreamReader(zip.GetEntry("word/styles.xml")!.Open(), Encoding.UTF8);
        styles.ReadToEnd().Should().Contain("w:ascii=\"Aptos\"", "Aptos is the document default");
        using var doc = new StreamReader(zip.GetEntry("word/document.xml")!.Open(), Encoding.UTF8);
        doc.ReadToEnd().Should().Contain("w:ascii=\"Aptos Display\"", "the title and headings use Aptos Display");
    }

    [Fact]
    public void Serialize_round_trips_through_parse()
    {
        var layout = ReportLayout.Parse("Outcome,!Summary,EventTimeline");
        var raw = ReportLayout.Serialize(layout);
        ReportLayout.Parse(raw).Should().Equal(layout);
    }

    [Fact]
    public void A_hidden_section_is_omitted_from_the_generated_word_document()
    {
        var enabled = new CaseReportModel
        {
            Sections = new[] { ReportSection.Summary, ReportSection.Outcome }, // BusinessImpact etc. hidden
            CaseNumber = "2026-09", Title = "Toggle test", Classification = "Incident", Phase = "Triage",
            Severity = "Low", Origin = "Internal detection", Summary = "SUMMARY_MARKER",
            GeneratedBy = "tester", GeneratedAtUtc = System.DateTimeOffset.UnixEpoch, ContentHash = new string('a', 64),
        };

        var xml = WordXml(new ReportGenerator().GenerateWord(enabled));
        xml.Should().Contain("Summary").And.Contain("Outcome");
        xml.Should().NotContain("Business Impact");
        xml.Should().NotContain("Systems Reviewed");
        // The integrity stamp is always present regardless of section toggles.
        xml.Should().Contain("Case content hash");
    }

    [Fact]
    public void Legal_data_context_and_impacted_assets_print_once_and_other_sections_point_there(/* BUG-81 */)
    {
        CaseReportModel Model(params ReportSection[] sections) => new()
        {
            Sections = sections,
            CaseNumber = "2026-09", Title = "Once", Classification = "Breach", Phase = "Recovery",
            Severity = "High", Origin = "Internal detection", Summary = "s",
            LegalReferred = true, LegalNote = "LEGAL_MARKER", LegalHold = true,
            DataTypesInvolved = "DATA_MARKER", ImpactedAssets = "ASSET_MARKER",
            GeneratedBy = "tester", GeneratedAtUtc = System.DateTimeOffset.UnixEpoch, ContentHash = new string('a', 64),
        };
        static int Count(string xml, string s) => (xml.Length - xml.Replace(s, "").Length) / s.Length;

        var all = WordXml(new ReportGenerator().GenerateWord(Model(ReportSection.BusinessImpact, ReportSection.SystemsReviewed, ReportSection.Outcome)));
        foreach (var marker in new[] { "LEGAL_MARKER", "DATA_MARKER", "ASSET_MARKER", "Legal hold in effect" })
            Count(all, marker).Should().Be(1, marker);
        all.Should().Contain("Impacted assets: see Business Impact.").And.Contain("Legal/Privacy: see Business Impact.");

        // Without Business Impact, the facts at the top hold them.
        var noImpact = WordXml(new ReportGenerator().GenerateWord(Model(ReportSection.SystemsReviewed, ReportSection.Outcome)));
        foreach (var marker in new[] { "LEGAL_MARKER", "DATA_MARKER", "ASSET_MARKER" })
            Count(noImpact, marker).Should().Be(1, marker);
    }

    private static readonly System.DateTimeOffset At = new(2026, 3, 4, 10, 0, 0, System.TimeSpan.Zero);

    private static CaseReportModel VendorCase(bool withImpact) => new()
    {
        Sections = withImpact ? System.Enum.GetValues<ReportSection>() : [ReportSection.EventTimeline, ReportSection.SystemsReviewed, ReportSection.Outcome],
        CaseNumber = "2026-09", Title = "Vendor", Classification = "Breach", Phase = "Closed", Severity = "High",
        Origin = "Third party", VendorName = "Acme", ImpactedAssets = "srv1", LegalReferred = true, LegalNote = "Counsel engaged.",
        DataTypesInvolved = "SSNs",
        ActivityBeganAtUtc = At, ActivityBeganApproximate = "the first attack step is dated only", DetectedAtUtc = At.AddHours(2),
        ResolvedAtUtc = At.AddHours(8), ClosedAtUtc = At.AddDays(2), ChangedAfterClosure = "Changed 2 times after closure by Dana.",
        DisclosureMilestones = [new ReportTimelineItem(At, "Vendor notified", "They told us", "email")],
        AttackChain = [new ReportAttackStep(1, At, "Initial Access", "actor", "host", "T1566", "Phish", "Vendor"),
            new ReportAttackStep(2, At.AddHours(1), "Execution", "actor", "srv1", null, "Ran", "Our environment")],
        Entities = [new ReportEntityRow("Host", "srv1", null, "Malicious", null, "EDR", "TLP:RED")],
        GeneratedBy = "tester", GeneratedAtUtc = At, ContentHash = new string('a', 64),
    };

    [Fact]
    public void The_preview_helpers_carry_what_the_Word_report_prints(/* BUG-517 */)
    {
        var m = VendorCase(withImpact: false);
        m.AttackChainHeaders.Should().Contain("Where");
        m.AttackChainRow(m.AttackChain[1])[2].Should().Be("Our environment");
        m.AttackChainCaption.Should().Contain("Acme's environment").And.Contain("after the pivot");
        CaseReportModel.EntityHeaders.Should().Contain("TLP");
        CaseReportModel.EntityRow(m.Entities[0]).Should().Contain("TLP:RED");
        m.OutcomeStamps.Should().Equal(
            "Activity began: 2026-03-04 10:00:00Z (approximate: the first attack step is dated only)",
            "Detected: 2026-03-04 12:00:00Z", "Recovery started: 2026-03-04 18:00:00Z", "Closed: 2026-03-06 10:00:00Z");
        m.SystemsImpactedAssetsLine.Should().Be("Impacted assets: srv1");
        m.OutcomeLegalPointer.Should().Be("Legal/Privacy: see the case facts at the top.");
        m.FactsLines.Should().Equal("Data context (analyst notes): SSNs", "Legal/Privacy referral recorded. Counsel engaged.");

        // Every line the preview renders from the model is in the Word report too.
        var xml = WordXml(new ReportGenerator().GenerateWord(m));
        foreach (var text in m.AttackChainHeaders.Concat(m.AttackChain.SelectMany(m.AttackChainRow).Where(c => c.Length > 0))
                     .Concat(CaseReportModel.EntityRow(m.Entities[0]).Where(c => c.Length > 0))
                     .Concat(m.DisclosureMilestones.SelectMany(CaseReportModel.DisclosureRow).Where(c => c.Length > 0))
                     .Concat(m.OutcomeStamps).Concat(m.FactsLines)
                     .Append(m.AttackChainCaption).Append(CaseReportModel.DisclosureCaption).Append(m.SystemsImpactedAssetsLine!)
                     .Append(m.OutcomeLegalPointer!).Append(m.ChangedAfterClosure!))
            xml.Should().Contain(text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;"), "the Word report prints \"{0}\" too", text);

        var withImpact = VendorCase(withImpact: true);
        withImpact.SystemsImpactedAssetsLine.Should().Be("Impacted assets: see Business Impact.");
        withImpact.OutcomeLegalPointer.Should().Be("Legal/Privacy: see Business Impact.");
        withImpact.FactsLines.Should().Equal("Legal/Privacy referral, data context: see Business Impact.");
        withImpact.BusinessImpactLines.Should().Contain("Impacted assets: srv1").And.Contain("Legal/Privacy referral recorded. Counsel engaged.");
    }

    [Fact]
    public void An_internal_case_keeps_its_six_column_attack_chain(/* BUG-517 */)
    {
        var m = VendorCase(withImpact: false) with { VendorName = null, DisclosureMilestones = [] };
        m.IsVendorCase.Should().BeFalse();
        m.ShowsAttackChain.Should().BeTrue();
        m.AttackChainHeaders.Should().HaveCount(6).And.NotContain("Where");
        m.AttackChainRow(m.AttackChain[0]).Should().HaveCount(6);
        (m with { AttackChain = [] }).ShowsAttackChain.Should().BeTrue("an internal case prints the table with (none)");
        (VendorCase(false) with { AttackChain = [] }).ShowsAttackChain.Should().BeFalse("a vendor case without steps shows the milestones only");
    }

    private static string WordXml(byte[] docx)
    {
        using var zip = new ZipArchive(new MemoryStream(docx), ZipArchiveMode.Read);
        using var s = zip.GetEntry("word/document.xml")!.Open();
        return new StreamReader(s, Encoding.UTF8).ReadToEnd();
    }

    [Fact]
    public void A_template_row_hashes_as_before_unless_it_is_the_lessons_default()
    {
        var t = new IncidentManager.Domain.Entities.ReportTemplate
        {
            Name = "House", FileName = "house.docx", Sha256 = "ab", SizeBytes = 1, CreatedBy = "admin",
            CreatedAtUtc = new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero),
        };
        t.BuildCanonicalContent().Should().Be("House|house.docx|ab|1|True|admin|2026-09-01T00:00:00.0000000+00:00");
        t.IsLessonsDefault = true;
        t.BuildCanonicalContent().Should().EndWith("|lessons-default");
    }

    [Fact]
    public void Review_and_improvement_fields_are_known_template_fields()
    {
        foreach (var f in new[] { "report.type", "review.what_happened", "review.opportunities", "improvement.title", "improvement.outcome" })
            IncidentManager.Application.Reporting.ReportTemplateFields.IsKnown(f).Should().BeTrue(f);
        IncidentManager.Application.Reporting.ReportTemplateFields.CollectionFor("improvement.owner").Should().Be("improvement");
    }
}
