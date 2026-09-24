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
        return (main.Document.Body!.InnerText,
            string.Concat(main.HeaderParts.Select(h => h.Header.InnerText)),
            string.Concat(main.FooterParts.Select(f => f.Footer.InnerText)),
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

    [Fact]
    public void The_starter_template_passes_its_own_check()
    {
        var check = _engine.Check(_engine.Starter());

        check.Ok.Should().BeTrue(string.Join("; ", check.Problems));
        check.Placeholders.Should().Contain(["case.title", "ioc.value", "image.attack_chain", "report.tlp"]);
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
    public void Non_word_files_and_fieldless_documents_are_rejected()
    {
        _engine.Check("not a docx"u8.ToArray()).Problems.Should().ContainSingle(p => p.Contains("readable Word document"));
        _engine.Check(Doc(["Just a letterhead"])).Problems.Should().Contain(p => p.Contains("no {{"));
    }
}
