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
