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
        var expected = System.Enum.GetValues<ReportSection>().Where(s => s != ReportSection.AnalystNotes);
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
        new ReportGenerator().GeneratePdf(Model(ReportSection.AnalystNotes)).Should().NotBeEmpty();
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
        var expected = System.Enum.GetValues<ReportSection>().Where(s => s != ReportSection.AnalystNotes).ToList();
        var resolved = ReportLayout.Resolve("Outcome,Summary");
        resolved.Should().StartWith(ReportSection.Outcome);
        resolved.Should().Contain(expected); // none dropped
        resolved.Count.Should().Be(expected.Count);
    }

    [Fact]
    public void Unknown_and_duplicate_tokens_are_ignored()
    {
        var resolved = ReportLayout.Resolve("Summary,Bogus,Summary,Appendix");
        resolved.Count(s => s == ReportSection.Summary).Should().Be(1);
        resolved.Should().Contain(ReportSection.Appendix);
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
}
