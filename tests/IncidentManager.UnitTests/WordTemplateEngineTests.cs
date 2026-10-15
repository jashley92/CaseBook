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

    // BUG-467: a paragraph anchoring a text box, as Word writes it: the box's paragraphs once in the drawing (wps) and
    // again in the VML fallback.
    private static Paragraph TextBoxAnchor(string before, params Paragraph[] inBox)
    {
        var inner = string.Concat(inBox.Select(p => p.OuterXml));
        return new Paragraph($"""
            <w:p xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
                 xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
                 xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
                 xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
                 xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape"
                 xmlns:v="urn:schemas-microsoft-com:vml">
              <w:r><w:t xml:space="preserve">{before}</w:t></w:r>
              <w:r><mc:AlternateContent>
                <mc:Choice Requires="wps"><w:drawing><wp:anchor distT="0" distB="0" distL="0" distR="0" simplePos="0" relativeHeight="1"
                    behindDoc="0" locked="0" layoutInCell="1" allowOverlap="1"><wp:simplePos x="0" y="0"/>
                  <wp:positionH relativeFrom="column"><wp:posOffset>0</wp:posOffset></wp:positionH>
                  <wp:positionV relativeFrom="paragraph"><wp:posOffset>0</wp:posOffset></wp:positionV>
                  <wp:extent cx="1828800" cy="914400"/><wp:effectExtent l="0" t="0" r="0" b="0"/><wp:wrapSquare wrapText="bothSides"/>
                  <wp:docPr id="1" name="Text Box 1"/><wp:cNvGraphicFramePr/>
                  <a:graphic><a:graphicData uri="http://schemas.microsoft.com/office/word/2010/wordprocessingShape">
                    <wps:wsp><wps:cNvSpPr txBox="1"/><wps:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="1828800" cy="914400"/></a:xfrm>
                      <a:prstGeom prst="rect"><a:avLst/></a:prstGeom></wps:spPr>
                      <wps:txbx><w:txbxContent>{inner}</w:txbxContent></wps:txbx><wps:bodyPr/></wps:wsp>
                  </a:graphicData></a:graphic></wp:anchor></w:drawing></mc:Choice>
                <mc:Fallback><w:pict><v:shape id="Text Box 1" style="width:144pt;height:72pt" type="#_x0000_t202">
                  <v:textbox><w:txbxContent>{inner}</w:txbxContent></v:textbox></v:shape></w:pict></mc:Fallback>
              </mc:AlternateContent></w:r>
            </w:p>
            """);
    }

    private static byte[] DocWithParts(OpenXmlElement[] body, Paragraph[]? header = null)
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document, true))
        {
            var main = doc.AddMainDocumentPart();
            main.Document = new Document(new Body(body));
            if (header is not null)
            {
                var part = main.AddNewPart<HeaderPart>();
                part.Header = new Header(header);
                main.Document.Body!.AppendChild(new SectionProperties(
                    new HeaderReference { Type = HeaderFooterValues.Default, Id = main.GetIdOfPart(part) }));
            }
            main.Document.Save();
        }
        return ms.ToArray();
    }

    private static List<List<string>> BoxContents(OpenXmlElement root) =>
        root.Descendants().Where(e => e.LocalName == "txbxContent")
            .Select(b => b.Elements<Paragraph>().Select(p => p.InnerText).ToList()).ToList();

    [Fact]
    public void A_field_split_across_runs_in_a_text_box_passes_the_check_and_fills(/* BUG-467 */)
    {
        var template = DocWithParts([TextBoxAnchor("Case: ", new Paragraph(R("{{case."), R("title}}"))),
            new Paragraph(R("{{report.tlp}}"))]);

        var check = _engine.Check(template);
        check.Problems.Should().BeEmpty();
        check.Placeholders.Should().Contain("case.title");
        check.Fillable.Should().Contain("case.title");

        using var result = WordprocessingDocument.Open(new MemoryStream(_engine.Render(template, Model())), false);
        BoxContents(result.MainDocumentPart!.Document!.Body!).Should().HaveCount(2)
            .And.AllSatisfy(b => b.Should().Equal("Credential-phishing wave"));
    }

    [Fact]
    public void A_list_in_a_text_box_repeats_inside_the_box(/* BUG-467 */)
    {
        var template = DocWithParts([TextBoxAnchor("Case {{case.number}}", new Paragraph(R("Indicators")), new Paragraph(R("{{ioc.value}}"))),
            new Paragraph(R("{{report.tlp}}"))]);

        using var result = WordprocessingDocument.Open(new MemoryStream(_engine.Render(template, Model())), false);
        var body = result.MainDocumentPart!.Document!.Body!;
        body.Elements<Paragraph>().Should().HaveCount(2, "the anchoring paragraph isn't repeated per indicator");
        body.Descendants<Drawing>().Should().ContainSingle("no stacked text boxes");
        BoxContents(body).Should().HaveCount(2, "the drawing and its VML fallback")
            .And.AllSatisfy(b => b.Should().Equal("Indicators", "203[.]0[.]113[.]66", "hxxps://evil[.]test"));
        new DocumentFormat.OpenXml.Validation.OpenXmlValidator().Validate(result).Should().BeEmpty();
    }

    [Fact]
    public void An_empty_list_in_a_text_box_keeps_the_anchoring_paragraph_and_the_box(/* BUG-467 */)
    {
        var template = DocWithParts([TextBoxAnchor("Case {{case.number}}", new Paragraph(R("{{ioc.value}}"))),
            new Paragraph(R("{{report.tlp}}"))]);

        using var result = WordprocessingDocument.Open(new MemoryStream(_engine.Render(template, Model(withIocs: false))), false);
        var body = result.MainDocumentPart!.Document!.Body!;
        body.Elements<Paragraph>().First().Descendants<Text>().First().Text.Should().Be("Case 2026-01_Phishing_Wave");
        BoxContents(body).Should().HaveCount(2).And.AllSatisfy(b => b.Should().Equal([""], "a text box must end in a paragraph"));
        new DocumentFormat.OpenXml.Validation.OpenXmlValidator().Validate(result).Should().BeEmpty();
    }

    [Fact]
    public void A_paragraph_and_its_text_box_of_the_same_list_repeat_together_per_item(/* BUG-467 */)
    {
        var template = DocWithParts([TextBoxAnchor("{{ioc.value}}", new Paragraph(R("{{ioc.type}}"))),
            new Paragraph(R("{{report.tlp}}"))]);

        using var result = WordprocessingDocument.Open(new MemoryStream(_engine.Render(template, Model())), false);
        var body = result.MainDocumentPart!.Document!.Body!;
        var cards = body.Elements<Paragraph>().SkipLast(1).ToList();
        cards.Should().HaveCount(2, "one paragraph, with its box, per indicator");
        cards.Select(c => c.Descendants<Text>().First().Text).Should().Equal("203[.]0[.]113[.]66", "hxxps://evil[.]test");
        cards.Select(c => BoxContents(c).Select(b => string.Join("|", b)).Distinct().Single()).Should().Equal("IP Address", "Url");
    }

    [Fact]
    public void A_table_row_in_a_text_box_of_the_same_list_as_its_anchor_repeats_with_it_per_item(/* BUG-502 */)
    {
        // A card: the indicator in the anchoring paragraph, and a details table of the same indicator in its text box.
        var template = DocWithParts([CardWithTable(), new Paragraph(R("{{report.tlp}}"))]);

        using var result = WordprocessingDocument.Open(new MemoryStream(_engine.Render(template, Model())), false);
        var body = result.MainDocumentPart!.Document!.Body!;
        var cards = body.Elements<Paragraph>().SkipLast(1).ToList();
        cards.Should().HaveCount(2, "one paragraph, with its box, per indicator");
        cards.Select(c => c.Descendants<Text>().First().Text).Should().Equal("203[.]0[.]113[.]66", "hxxps://evil[.]test");
        cards.Select(c => string.Join("|", c.Descendants<TableRow>().Select(r => r.InnerText))).Should()
            .Equal("IP Address|IP Address", "Url|Url");   // each card's table (drawing and fallback) holds its own indicator only

        static Paragraph CardWithTable()
        {
            var p = TextBoxAnchor("{{ioc.value}}", new Paragraph(R("Type")));
            foreach (var box in p.Descendants().Where(e => e.LocalName == "txbxContent").ToList())
                box.AppendChild(new Table(new TableProperties(), new TableGrid(new GridColumn { Width = "2000" }),
                        new TableRow(new TableCell(new Paragraph(R("{{ioc.type}}"))))))
                    .InsertAfterSelf(new Paragraph());   // a text box ends in a paragraph
            return p;
        }
    }

    [Fact]
    public void A_list_in_a_text_box_in_a_table_cell_repeats_inside_the_box_not_the_row(/* BUG-467 */)
    {
        var cell = new TableCell(TextBoxAnchor("", new Paragraph(R("{{ioc.value}}"))));
        var template = DocWithParts([new Table(new TableRow(cell)), new Paragraph(R("{{report.tlp}}"))]);

        using var result = WordprocessingDocument.Open(new MemoryStream(_engine.Render(template, Model())), false);
        var body = result.MainDocumentPart!.Document!.Body!;
        body.Descendants<TableRow>().Should().ContainSingle();
        BoxContents(body).Should().HaveCount(2).And.AllSatisfy(b => b.Should().Equal("203[.]0[.]113[.]66", "hxxps://evil[.]test"));
    }

    [Fact]
    public void A_marking_in_a_header_text_box_is_found_and_filled(/* BUG-467 */)
    {
        var template = DocWithParts([new Paragraph(R("{{case.title}}"))],
            header: [TextBoxAnchor("", new Paragraph(R("{{report."), R("tlp}}")))]);

        var check = _engine.Check(template);
        check.Problems.Should().BeEmpty();
        check.Fillable.Should().Contain("report.tlp");

        using var result = WordprocessingDocument.Open(new MemoryStream(_engine.Render(template, Model())), false);
        BoxContents(result.MainDocumentPart!.HeaderParts.Single().Header!).Should().HaveCount(2)
            .And.AllSatisfy(b => b.Should().Equal("TLP:RED"));
    }
}
