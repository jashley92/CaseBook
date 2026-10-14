using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using FluentAssertions;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Reporting;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>PROD-47: customer Word templates are checked on upload and filled from the report model.</summary>
public class WordTemplateEngineTests
{
    private readonly WordTemplateEngine _engine = new();

    private static CaseReportModel Model(bool withIocs = true) => new()
    {
        CaseNumber = "2026-01_Phishing_Wave",
        Title = "Credential-phishing wave",
        Classification = "Breach",
        Phase = "Containment",
        Severity = "Critical",
        Origin = "Internal detection",
        Summary = "First paragraph.\nSecond paragraph.",
        Tlp = TlpLevel.Red,
        IndicatorsDefanged = true,
        Iocs = withIocs
            ? [new ReportIocRow("IP Address", "203[.]0[.]113[.]66", "Malicious", null, DateTimeOffset.UnixEpoch, "SIEM", "egress"),
               new ReportIocRow("Url", "hxxps://evil[.]test", "Malicious", "TLP:RED", DateTimeOffset.UnixEpoch, null, null)]
            : [],
        AttackChainImages = [new SkiaReportDiagrams().AttackChain([new DiagramStep(1, DateTimeOffset.UnixEpoch, [MitreTactic.InitialAccess], "T1566", "a", "b")])[0]],
        GeneratedBy = "Dev Analyst",
        GeneratedAtUtc = DateTimeOffset.UnixEpoch,
        ContentHash = "abc123"
    };

    private static (string Body, string Header, string Footer, int Images, int Breaks) Read(byte[] docx)
    {
        using var doc = WordprocessingDocument.Open(new MemoryStream(docx), false);
        var main = doc.MainDocumentPart!;
        return (main.Document!.Body!.InnerText,
            string.Concat(main.HeaderParts.Select(h => h.Header!.InnerText)),
            string.Concat(main.FooterParts.Select(f => f.Footer!.InnerText)),
            main.ImageParts.Count(),
            main.Document.Body.Descendants<Break>().Count());
    }

    /// <summary>A minimal .docx whose body has the given paragraphs, each paragraph's runs given separately.</summary>
    private static byte[] Doc(params string[][] paragraphs)
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document, true))
        {
            var main = doc.AddMainDocumentPart();
            main.Document = new Document(new Body(paragraphs.Select(runs =>
                new Paragraph(runs.Select(r => new Run(new Text(r) { Space = SpaceProcessingModeValues.Preserve }))))));
            main.Document.Save();
        }
        return ms.ToArray();
    }

    private static Run R(string text) => new(new Text(text) { Space = SpaceProcessingModeValues.Preserve });

    private static byte[] DocWith(Paragraph p)
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document, true))
        {
            var main = doc.AddMainDocumentPart();
            main.Document = new Document(new Body(p, new Paragraph(R("{{report.tlp}}"))));
            main.Document.Save();
        }
        return ms.ToArray();
    }

    [Fact]
    public void A_marking_only_in_a_tracked_deletion_isnt_one_the_report_can_fill(/* BUG-166 */)
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document, true))
        {
            var main = doc.AddMainDocumentPart();
            var deleted = new DeletedRun(new Run(new DeletedText("{{report.tlp}}") { Space = SpaceProcessingModeValues.Preserve }))
                { Id = "1", Author = "Ana" };
            main.Document = new Document(new Body(new Paragraph(R("{{case.title}}")), new Paragraph(deleted)));
            main.Document.Save();
        }

        var check = _engine.Check(ms.ToArray());
        check.Placeholders.Should().Contain("report.tlp", "the text is there");
        check.Fillable.Should().Contain("case.title").And.NotContain("report.tlp", "a deletion isn't printed");
        _engine.Check(_engine.Starter()).Fillable.Should().Contain("report.tlp");
    }

    [Fact]
    public void A_template_that_doesnt_print_the_TLP_marking_is_refused(/* BUG-75 */)
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document, true))
        {
            var main = doc.AddMainDocumentPart();
            main.Document = new Document(new Body(new Paragraph(R("{{case.title}}"))));
            main.Document.Save();
        }

        _engine.Check(ms.ToArray()).Problems.Should().ContainSingle(p => p.Contains("{{report.tlp}}") && p.Contains("TLP marking"));
        _engine.Check(_engine.Starter()).Problems.Should().BeEmpty();
    }

    [Fact]
    public void A_field_split_inside_a_link_is_filled_and_one_split_across_its_edge_is_reported(/* BUG-76 */)
    {
        var inside = DocWith(new Paragraph(R("Case: "), new Hyperlink(R("{{case."), R("title}}")) { Anchor = "top" }));
        _engine.Check(inside).Problems.Should().BeEmpty();
        Read(_engine.Render(inside, Model())).Body.Should().StartWith("Case: Credential-phishing wave");

        var across = DocWith(new Paragraph(R("{{case."), new Hyperlink(R("title}}")) { Anchor = "top" }));
        _engine.Check(across).Problems.Should().Contain(p => p.Contains("{{case.title}}") && p.Contains("Retype it"));
    }

    [Fact]
    public void Case_text_that_looks_like_a_field_is_printed_as_typed(/* BUG-44 */)
    {
        var template = Doc(["Title: {{case.title}}"], ["{{ioc.value}}"]);
        var m = Model() with
        {
            Title = "Note says {{report.content_hash}}",
            Iocs = [new ReportIocRow("Url", "hxxps://x/{{case.title}}", "Malicious", null, DateTimeOffset.UnixEpoch, null, null)]
        };

        var body = Read(_engine.Render(template, m)).Body;

        body.Should().Contain("Title: Note says {{report.content_hash}}").And.Contain("hxxps://x/{{case.title}}");
        body.Should().NotContain("abc123");
    }

    [Fact]
    public void The_starter_template_passes_its_own_check()
    {
        var check = _engine.Check(_engine.Starter());

        check.Ok.Should().BeTrue(string.Join("; ", check.Problems));
        check.Placeholders.Should().Contain(["case.title", "ioc.value", "image.attack_chain", "report.tlp"]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void The_starters_state_their_page_size_and_margins(bool lessons)
    {
        // The Report tab's in-browser preview draws a page that states no size edge to edge; Word would assume Letter.
        using var ms = new MemoryStream(lessons ? _engine.LessonsStarter() : _engine.Starter());
        using var doc = WordprocessingDocument.Open(ms, false);
        var section = doc.MainDocumentPart!.Document!.Body!.Elements<SectionProperties>().Single();
        section.GetFirstChild<PageSize>()!.Width!.Value.Should().Be(12240U);
        section.GetFirstChild<PageMargin>()!.Left!.Value.Should().Be(1440U);
        new DocumentFormat.OpenXml.Validation.OpenXmlValidator().Validate(doc).Should().BeEmpty();
    }

    [Fact]
    public void Rendering_fills_fields_repeats_rows_and_embeds_pictures()
    {
        var (body, header, footer, images, breaks) = Read(_engine.Render(_engine.Starter(), Model()));

        body.Should().Contain("2026-01_Phishing_Wave — Credential-phishing wave")
            .And.Contain("203[.]0[.]113[.]66").And.Contain("hxxps://evil[.]test").And.Contain("TLP:RED")
            .And.Contain("(none)", "empty lists (steps, relationships, actions) print one \"(none)\" row")
            .And.NotContain("{{");
        header.Should().Contain("TLP:RED");
        footer.Should().Contain("TLP:RED");
        images.Should().Be(1, "one attack-chain picture; no entity graph in this model");
        breaks.Should().BeGreaterThan(0, "a multi-line summary keeps its line breaks");
    }

    [Fact]
    public void A_field_split_across_runs_still_fills()
    {
        // Word often splits typed text into several runs.
        var template = Doc(["Case: {{case.", "title", "}} (", "{{case.severity}}", ")"]);

        Read(_engine.Render(template, Model())).Body.Should().Be("Case: Credential-phishing wave (Critical)");
    }

    [Fact]
    public void Unknown_fields_are_rejected_on_upload()
    {
        var check = _engine.Check(Doc(["{{case.title}} {{case.secret_sauce}}"]));

        check.Ok.Should().BeFalse();
        check.Problems.Should().ContainSingle(p => p.Contains("case.secret_sauce"));
    }

    [Fact]
    public void A_template_with_a_field_that_loads_or_runs_something_is_rejected(/* WF-39 */)
    {
        static Run Fc(FieldCharValues t) => new(new FieldChar { FieldCharType = t });
        static Run Code(string c) => new(new FieldCode(c) { Space = SpaceProcessingModeValues.Preserve });
        // INCLUDETEXT split across two runs, as Word writes it. A PAGE field is harmless.
        var split = DocWith(new Paragraph(Fc(FieldCharValues.Begin), Code(" INCLUDE"), Code("TEXT \"https://files.example/x.docx\" "),
            Fc(FieldCharValues.Separate), R("x"), Fc(FieldCharValues.End)));
        _engine.Check(split).Problems.Should().Contain(p => p.Contains("INCLUDETEXT"));

        var dde = DocWith(new Paragraph(new SimpleField(R("x")) { Instruction = "DDEAUTO cmd.exe \"/c calc\"" }));
        _engine.Check(dde).Problems.Should().Contain(p => p.Contains("DDEAUTO"));

        var page = DocWith(new Paragraph(Fc(FieldCharValues.Begin), Code(" PAGE "), Fc(FieldCharValues.Separate), R("1"), Fc(FieldCharValues.End),
            new Run(new Text(" HYPERLINK in text isn't a field"))));
        _engine.Check(page).Problems.Should().BeEmpty();
    }

    [Fact]
    public void A_template_that_loads_outside_content_is_rejected()
    {
        var bytes = Doc(["{{case.title}}"]);
        using var ms = new MemoryStream();
        ms.Write(bytes);
        using (var doc = WordprocessingDocument.Open(ms, true))
            doc.MainDocumentPart!.AddExternalRelationship(
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image", new Uri("http://tracker.example/pixel.png"));

        var check = _engine.Check(ms.ToArray());

        check.Ok.Should().BeFalse();
        check.Problems.Should().Contain(p => p.Contains("outside the document"));
    }

    [Fact]
    public void A_document_whose_xml_is_truncated_is_reported_not_thrown(/* BUG-360 */)
    {
        var docx = Doc(["{{case.number}} {{report.tlp}}"]);
        using var ms = new MemoryStream();
        ms.Write(docx);
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Update, leaveOpen: true))
        {
            var entry = zip.GetEntry("word/document.xml")!;
            string xml;
            using (var r = new StreamReader(entry.Open())) xml = r.ReadToEnd();
            entry.Delete();
            using var w = new StreamWriter(zip.CreateEntry("word/document.xml").Open());
            w.Write(xml[..(xml.Length / 2)]);
        }

        _engine.Check(ms.ToArray()).Problems.Should().ContainSingle(p => p.Contains("readable Word document"));
    }

    [Fact]
    public void Non_word_files_and_fieldless_documents_are_rejected()
    {
        _engine.Check("not a docx"u8.ToArray()).Problems.Should().ContainSingle(p => p.Contains("readable Word document"));
        _engine.Check(Doc(["Just a letterhead"])).Problems.Should().Contain(p => p.Contains("no {{"));
    }

    [Fact]
    public void A_list_table_inside_a_layout_table_repeats_its_own_rows_only(/* BUG-382 */)
    {
        // A one-row layout table whose cell holds a heading, a list table, and the marking.
        static TableRow Row(params string[] cells) => new(cells.Select(c => new TableCell(new Paragraph(R(c)))));
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document, true))
        {
            var main = doc.AddMainDocumentPart();
            var inner = new Table(Row("Type", "Indicator"), Row("{{ioc.type}}", "{{ioc.value}}"));
            var layout = new Table(new TableRow(new TableCell(
                new Paragraph(R("Case {{case.number}}")), inner, new Paragraph(R("{{report.tlp}}")))));
            main.Document = new Document(new Body(layout));
            main.Document.Save();
        }

        var filled = _engine.Render(ms.ToArray(), Model());

        using var result = WordprocessingDocument.Open(new MemoryStream(filled), false);
        var body = result.MainDocumentPart!.Document!.Body!;
        var outer = body.Elements<Table>().Single();
        outer.Elements<TableRow>().Should().ContainSingle("the layout row isn't repeated per indicator");
        body.InnerText.Split("Case 2026-01_Phishing_Wave").Length.Should().Be(2, "the case number prints once");
        var rows = outer.Descendants<Table>().Single().Elements<TableRow>().Select(r => r.InnerText).ToList();
        rows.Should().Equal("TypeIndicator", "IP Address203[.]0[.]113[.]66", "Urlhxxps://evil[.]test");
    }

    [Fact]
    public void A_card_row_with_a_nested_table_of_the_same_list_fills_it_per_item(/* BUG-382 follow-up */)
    {
        static TableRow Row(params string[] cells) => new(cells.Select(c => new TableCell(new Paragraph(R(c)))));
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document, true))
        {
            var main = doc.AddMainDocumentPart();
            var details = new Table(Row("{{ioc.type}}"));
            var cards = new Table(new TableRow(new TableCell(new Paragraph(R("{{ioc.value}}"))), new TableCell(details)));
            main.Document = new Document(new Body(cards));
            main.Document.Save();
        }

        var filled = _engine.Render(ms.ToArray(), Model());

        using var result = WordprocessingDocument.Open(new MemoryStream(filled), false);
        var rows = result.MainDocumentPart!.Document!.Body!.Elements<Table>().Single().Elements<TableRow>().ToList();
        rows.Should().HaveCount(2, "one card per indicator");
        rows.Select(r => r.Descendants<Table>().Single().Elements<TableRow>().Count()).Should().Equal([1, 1],
            "each card's details table holds that indicator only");
        rows[0].InnerText.Should().Be("203[.]0[.]113[.]66IP Address");
    }

    [Fact]
    public void A_picture_field_alone_in_a_cell_leaves_a_valid_cell_when_theres_no_picture(/* BUG-320 */)
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document, true))
        {
            var main = doc.AddMainDocumentPart();
            var cell = new TableCell(new Paragraph(R("{{image.entity_graph}}")));
            main.Document = new Document(new Body(new Table(new TableRow(cell)), new Paragraph(R("{{report.tlp}}"))));
            main.Document.Save();
        }

        var filled = _engine.Render(ms.ToArray(), Model());   // the model has no entity graph

        using var result = WordprocessingDocument.Open(new MemoryStream(filled), false);
        result.MainDocumentPart!.Document!.Body!.Descendants<TableCell>().Single().Elements<Paragraph>().Should().ContainSingle(
            "a cell must end in a paragraph");
    }
}
