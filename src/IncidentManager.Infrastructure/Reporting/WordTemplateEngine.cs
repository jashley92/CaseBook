using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using IncidentManager.Application.Reporting;

namespace IncidentManager.Infrastructure.Reporting;

/// <summary>
/// PROD-47: fills a customer-designed Word template from the report model with the Open XML SDK (no Word needed on
/// the server), checks uploads, and produces a starter template. Placeholders and their values come from
/// <see cref="ReportTemplateFields"/>. The template's own styles, fonts, headers and footers are kept — only the
/// <c>{{…}}</c> fields change.
/// </summary>
public sealed class WordTemplateEngine : IReportTemplateEngine
{
    // ── Checking an upload ───────────────────────────────────────────────────────────────────────

    public TemplateCheck Check(byte[] docx)
    {
        var problems = new List<string>();
        var found = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var ms = new MemoryStream(docx);
            using var doc = WordprocessingDocument.Open(ms, false);
            if (doc.DocumentType != WordprocessingDocumentType.Document)
                problems.Add("It's a macro-enabled or template-type Word file. Save it as a Word Document (.docx).");
            var main = doc.MainDocumentPart;
            if (main?.Document?.Body is null) return new TemplateCheck(["It has no document body."], []);

            // A report goes to people outside the SOC: nothing in it may run code or fetch anything when opened.
            var parts = AllParts(doc).ToList();
            if (main.VbaProjectPart is not null || parts.OfType<VbaProjectPart>().Any())
                problems.Add("It contains macros.");
            if (parts.Any(p => p is EmbeddedObjectPart or EmbeddedPackagePart or EmbeddedControlPersistencePart
                    or EmbeddedControlPersistenceBinaryDataPart))
                problems.Add("It contains embedded objects (OLE or ActiveX). Remove them.");
            var external = parts.Cast<OpenXmlPartContainer>().Prepend(doc)
                .SelectMany(p => p.ExternalRelationships)
                .Select(r => r.RelationshipType.Split('/')[^1])
                .Distinct()
                .ToList();
            if (external.Count > 0)
                problems.Add($"It loads content from outside the document ({string.Join(", ", external)}). Embed pictures instead " +
                             "of linking them, and detach any attached template (File → Options → Add-ins → Templates).");

            foreach (var (root, inBody) in Roots(main))
            {
                foreach (var p in root.Descendants<Paragraph>())
                {
                    foreach (System.Text.RegularExpressions.Match match in ReportTemplateFields.Placeholder().Matches(p.InnerText))
                    {
                        var name = match.Groups[1].Value.ToLowerInvariant();
                        found.Add(name);
                        if (!inBody && name.StartsWith("image.", StringComparison.Ordinal))
                            problems.Add($"{{{{{name}}}}} is in a header or footer; pictures can only go in the body.");
                    }
                }
            }
        }
        catch (Exception e) when (e is OpenXmlPackageException or InvalidDataException or FileFormatException or IOException)
        {
            return new TemplateCheck(["It isn't a readable Word document (.docx)."], []);
        }

        var unknown = found.Where(n => !ReportTemplateFields.IsKnown(n)).ToList();
        if (unknown.Count > 0)
            problems.Add("Unknown field(s): " + string.Join(", ", unknown.Select(n => $"{{{{{n}}}}}")) + ". See the field reference.");
        if (found.Count == 0)
            problems.Add("It has no {{…}} fields. Start from the starter template, or add fields from the field reference.");
        return new TemplateCheck(problems.Distinct().ToList(), found.ToList());
    }

    private static IEnumerable<OpenXmlPart> AllParts(OpenXmlPartContainer root)
    {
        var seen = new HashSet<OpenXmlPart>();
        var stack = new Stack<OpenXmlPart>(root.Parts.Select(p => p.OpenXmlPart));
        while (stack.Count > 0)
        {
            var part = stack.Pop();
            if (!seen.Add(part)) continue;
            yield return part;
            foreach (var child in part.Parts) stack.Push(child.OpenXmlPart);
        }
    }

    private static IEnumerable<(OpenXmlElement Root, bool InBody)> Roots(MainDocumentPart main)
    {
        yield return (main.Document.Body!, true);
        foreach (var h in main.HeaderParts) if (h.Header is not null) yield return (h.Header, false);
        foreach (var f in main.FooterParts) if (f.Footer is not null) yield return (f.Footer, false);
    }

    // ── Rendering ────────────────────────────────────────────────────────────────────────────────

    public byte[] Render(byte[] template, CaseReportModel m)
    {
        using var ms = new MemoryStream();
        ms.Write(template);
        ms.Position = 0;
        using (var doc = WordprocessingDocument.Open(ms, true))
        {
            var main = doc.MainDocumentPart!;
            Fill(main.Document.Body!, m, main);
            main.Document.Save();
            foreach (var h in main.HeaderParts) { Fill(h.Header, m, null); h.Header.Save(); }
            foreach (var f in main.FooterParts) { Fill(f.Footer, m, null); f.Footer.Save(); }
        }
        return ms.ToArray();
    }

    private static void Fill(OpenXmlElement root, CaseReportModel m, MainDocumentPart? pictures)
    {
        // Word splits typed text across runs ("{{case." + "title}}"); rejoin the runs a field spans first.
        foreach (var p in root.Descendants<Paragraph>().ToList()) JoinSplitFields(p);

        // Pictures: a paragraph holding only an image field becomes the picture(s).
        foreach (var p in root.Descendants<Paragraph>().ToList())
        {
            var text = p.InnerText.Trim();
            IReadOnlyList<byte[]>? images = Is(text, ReportTemplateFields.AttackChainImage) ? m.AttackChainImages
                : Is(text, ReportTemplateFields.EntityGraphImage) ? (m.EntityGraphImage is { } g ? [g] : [])
                : null;
            if (images is null) continue;
            var alt = Is(text, ReportTemplateFields.AttackChainImage) ? CaseReportModel.AttackChainAlt : CaseReportModel.EntityGraphAlt;
            if (pictures is not null)
                foreach (var png in images) p.InsertBeforeSelf(ReportGenerator.BodyPicture(pictures, png, "Report picture", alt));
            p.Remove();
        }

        // Lists: a table row, or a paragraph outside a table, that uses a list's fields repeats per item.
        foreach (var row in root.Descendants<TableRow>().ToList())
            if (ListIn(row.InnerText) is { } prefix) Repeat(row, prefix, m, emptyText: "(none)");
        foreach (var p in root.Descendants<Paragraph>().Where(p => !p.Ancestors<Table>().Any()).ToList())
            if (ListIn(p.InnerText) is { } prefix) Repeat(p, prefix, m, emptyText: null);

        // Everything else: single values (unknown or out-of-place fields become blank).
        Replace(root, name => ReportTemplateFields.Scalar(m, name));
    }

    private static bool Is(string text, string field) =>
        ReportTemplateFields.Placeholder().Match(text) is { Success: true } mt && mt.Value.Length == text.Length
        && mt.Groups[1].Value.Equals(field, StringComparison.OrdinalIgnoreCase);

    private static string? ListIn(string text) =>
        ReportTemplateFields.Placeholder().Matches(text)
            .Select(mt => ReportTemplateFields.CollectionFor(mt.Groups[1].Value))
            .FirstOrDefault(p => p is not null);

    /// <summary>One copy of <paramref name="block"/> per item; with no items, one "(none)" row (or nothing).</summary>
    private static void Repeat(OpenXmlElement block, string prefix, CaseReportModel m, string? emptyText)
    {
        var items = ReportTemplateFields.Items(m, prefix);
        foreach (var item in items)
        {
            var copy = (OpenXmlElement)block.CloneNode(true);
            Replace(copy, name => ReportTemplateFields.CollectionFor(name) == prefix ? item(name) : null);
            block.InsertBeforeSelf(copy);
        }
        if (items.Count == 0 && emptyText is not null)
        {
            var copy = (OpenXmlElement)block.CloneNode(true);
            Replace(copy, name => ReportTemplateFields.CollectionFor(name) == prefix ? "" : null);
            if (copy.Descendants<Text>().FirstOrDefault() is { } first) first.Text = emptyText + first.Text;
            block.InsertBeforeSelf(copy);
        }
        block.Remove();
    }

    /// <summary>Replaces fields in every text node; a null from <paramref name="value"/> leaves that field for later.</summary>
    private static void Replace(OpenXmlElement root, Func<string, string?> value)
    {
        foreach (var t in root.Descendants<Text>().ToList())
        {
            if (!t.Text.Contains("{{", StringComparison.Ordinal)) continue;
            var replaced = ReportTemplateFields.Placeholder().Replace(t.Text, mt => value(mt.Groups[1].Value) ?? mt.Value);
            SetText(t, replaced);
        }
    }

    /// <summary>Sets a text node, turning line breaks in the value into Word line breaks within the same run.</summary>
    private static void SetText(Text t, string value)
    {
        var lines = value.Replace("\r\n", "\n").Split('\n');
        t.Text = lines[0];
        t.Space = SpaceProcessingModeValues.Preserve;
        OpenXmlElement after = t;
        foreach (var line in lines.Skip(1))
        {
            var br = new Break();
            after.InsertAfterSelf(br);
            var next = new Text(line) { Space = SpaceProcessingModeValues.Preserve };
            br.InsertAfterSelf(next);
            after = next;
        }
    }

    /// <summary>Merges only the runs a <c>{{…}}</c> field is split across, keeping the first run's formatting.</summary>
    private static void JoinSplitFields(Paragraph p)
    {
        var runs = p.Elements<Run>().ToList();
        if (runs.Count < 2) return;
        var texts = runs.Select(r => string.Concat(r.Elements<Text>().Select(t => t.Text))).ToList();
        var full = string.Concat(texts);
        if (!full.Contains("{{", StringComparison.Ordinal)) return;

        var starts = new int[runs.Count];
        for (int i = 0, pos = 0; i < runs.Count; pos += texts[i].Length, i++) starts[i] = pos;
        int RunAt(int offset)
        {
            for (var i = runs.Count - 1; i >= 0; i--)
                if (starts[i] <= offset && texts[i].Length > 0) return i;
            return 0;
        }

        // Groups of consecutive runs to merge, from the fields that span more than one run.
        var groups = new List<(int From, int To)>();
        foreach (System.Text.RegularExpressions.Match mt in ReportTemplateFields.Placeholder().Matches(full))
        {
            var (a, b) = (RunAt(mt.Index), RunAt(mt.Index + mt.Length - 1));
            if (a == b) continue;
            if (groups.Count > 0 && a <= groups[^1].To) groups[^1] = (groups[^1].From, Math.Max(b, groups[^1].To));
            else groups.Add((a, b));
        }

        for (var g = groups.Count - 1; g >= 0; g--)
        {
            var (from, to) = groups[g];
            var merged = string.Concat(texts.Skip(from).Take(to - from + 1));
            var first = runs[from];
            foreach (var t in first.Elements<Text>().ToList()) t.Remove();
            first.AppendChild(new Text(merged) { Space = SpaceProcessingModeValues.Preserve });
            for (var i = from + 1; i <= to; i++) runs[i].Remove();
        }
    }

    // ── Starter template ─────────────────────────────────────────────────────────────────────────

    public byte[] Starter()
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document, true))
        {
            var main = doc.AddMainDocumentPart();
            main.Document = new Document();
            var body = main.Document.AppendChild(new Body());

            body.AppendChild(ReportGenerator.P("{{case.number}} — {{case.title}}", bold: true, size: 32));
            body.AppendChild(ReportGenerator.P("Classification: {{case.classification}}    Phase: {{case.phase}}    Severity: {{case.severity}}", size: 20));
            body.AppendChild(ReportGenerator.P("Detected: {{case.detected}}    Contained: {{case.contained}}    Closed: {{case.closed}}", size: 20));
            body.AppendChild(ReportGenerator.P("{{report.sharing}}", italic: true, size: 20));

            body.AppendChild(ReportGenerator.Heading("Summary"));
            body.AppendChild(ReportGenerator.P("{{case.summary}}"));

            body.AppendChild(ReportGenerator.Heading("Business impact"));
            body.AppendChild(ReportGenerator.P("Affected individuals: {{case.affected_individuals}}    Data elements: {{case.data_elements}}", size: 20));
            body.AppendChild(ReportGenerator.P("Jurisdictions: {{case.jurisdictions}}    Materiality: {{case.materiality}}", size: 20));

            body.AppendChild(ReportGenerator.Heading("Attack chain"));
            body.AppendChild(ReportGenerator.P("{{image.attack_chain}}"));
            body.AppendChild(ReportGenerator.WordTable(["#", "When (UTC)", "Tactic(s)", "Actor", "Target", "Technique", "What happened"],
                [["{{step.number}}", "{{step.when}}", "{{step.tactics}}", "{{step.actor}}", "{{step.target}}", "{{step.technique}}", "{{step.description}}"]]));

            body.AppendChild(ReportGenerator.Heading("Indicators of compromise"));
            body.AppendChild(ReportGenerator.P("{{report.defang_note}}", italic: true, size: 18));
            body.AppendChild(ReportGenerator.WordTable(["Type", "Indicator", "Verdict", "TLP", "Added", "Context"],
                [["{{ioc.type}}", "{{ioc.value}}", "{{ioc.verdict}}", "{{ioc.tlp}}", "{{ioc.added}}", "{{ioc.context}}"]]));

            body.AppendChild(ReportGenerator.Heading("Relationships"));
            body.AppendChild(ReportGenerator.P("{{image.entity_graph}}"));
            body.AppendChild(ReportGenerator.WordTable(["From", "Relationship", "To", "Notes"],
                [["{{relationship.source}}", "{{relationship.relationship}}", "{{relationship.target}}", "{{relationship.notes}}"]]));

            body.AppendChild(ReportGenerator.Heading("Recommendations"));
            body.AppendChild(ReportGenerator.WordTable(["Task", "Owner", "Due", "Status"],
                [["{{action.task}}", "{{action.owner}}", "{{action.due}}", "{{action.status}}"]]));

            body.AppendChild(ReportGenerator.P("Generated by {{report.generated_by}} at {{report.generated_at}}. Case content hash: {{report.content_hash}}",
                italic: true, size: 16));

            // Header and footer carry the TLP marking, as the built-in report does.
            var headerPart = main.AddNewPart<HeaderPart>();
            headerPart.Header = new Header(
                new Paragraph(new ParagraphProperties(new Justification { Val = JustificationValues.Right }),
                    new Run(new RunProperties(new Bold()), new Text("{{report.tlp}}"))),
                new Paragraph(new ParagraphProperties(new Justification { Val = JustificationValues.Center }),
                    new Run(new RunProperties(new Bold()), new Text("{{org.name}}"))));
            var footerPart = main.AddNewPart<FooterPart>();
            footerPart.Footer = new Footer(
                new Paragraph(new ParagraphProperties(new Justification { Val = JustificationValues.Right }),
                    new Run(new RunProperties(new Bold()), new Text("{{report.tlp}}"))),
                ReportGenerator.PageNumberParagraph());
            body.AppendChild(new SectionProperties(
                new HeaderReference { Type = HeaderFooterValues.Default, Id = main.GetIdOfPart(headerPart) },
                new FooterReference { Type = HeaderFooterValues.Default, Id = main.GetIdOfPart(footerPart) }));
            main.Document.Save();
        }
        return ms.ToArray();
    }
}
