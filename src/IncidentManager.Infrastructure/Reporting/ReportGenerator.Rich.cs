using System.Globalization;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Wordprocessing;
using IncidentManager.Application.Content;

namespace IncidentManager.Infrastructure.Reporting;

/// <summary>
/// Word rendering of analyst Markdown (Summary, notes, the post-incident review) with its formatting kept:
/// headings, bold/italic, bulleted and numbered lists (nested), quotes and code. Parsed once into
/// <see cref="RichBlock"/>s by <see cref="RichText"/> so Word, PDF and the in-app preview agree. Lists use a
/// printed marker + hanging indent rather than Word numbering definitions, so numbering is exactly what the
/// analyst wrote and survives copy/paste between documents.
/// </summary>
public sealed partial class ReportGenerator
{
    private const int WordIndentPerLevel = 360;   // twips (0.25")

    private static void AppendRich(Body body, IReadOnlyList<RichBlock> blocks, string empty = "(not provided)")
    {
        if (blocks.Count == 0)
        {
            body.AppendChild(P(empty));
            return;
        }
        foreach (var b in blocks)
            body.AppendChild(RichParagraph(b));
    }

    private static Paragraph RichParagraph(RichBlock b)
    {
        var spacing = new SpacingBetweenLines { Before = "0", After = "80" };
        Indentation? indent = null;
        var size = 22;
        bool bold = false, italic = false, code = false;
        string? color = null;

        switch (b.Kind)
        {
            case RichBlockKind.Heading:
                // An analyst's heading sits *inside* a report section/field, so it stays subordinate to the
                // report's own slate headings and labels: bold, dark, only a step above body size.
                size = b.Level switch { 1 => 25, 2 => 24, _ => 23 };
                bold = true;
                spacing.Before = "120";
                break;
            case RichBlockKind.Bullet or RichBlockKind.Numbered:
                indent = new Indentation
                {
                    Left = ((b.Level + 1) * WordIndentPerLevel).ToString(CultureInfo.InvariantCulture),
                    Hanging = WordIndentPerLevel.ToString(CultureInfo.InvariantCulture)
                };
                spacing.After = "40";
                break;
            case RichBlockKind.Paragraph when b.Level > 0:   // a paragraph continuing a list item
                indent = new Indentation { Left = (b.Level * WordIndentPerLevel).ToString(CultureInfo.InvariantCulture) };
                break;
            case RichBlockKind.Quote:
                indent = new Indentation { Left = WordIndentPerLevel.ToString(CultureInfo.InvariantCulture) };
                italic = true;
                color = "595959";
                break;
            case RichBlockKind.Code:
                indent = new Indentation { Left = (WordIndentPerLevel / 2).ToString(CultureInfo.InvariantCulture) };
                code = true;
                size = 18;
                break;
        }
        // Schema order within pPr: spacing before ind.
        var pPr = new ParagraphProperties(spacing);
        if (indent is not null) pPr.Append(indent);
        var p = new Paragraph(pPr);

        if (b.Kind is RichBlockKind.Bullet or RichBlockKind.Numbered)
        {
            p.AppendChild(WordRun(b.Marker ?? "•", false, false, false, null, size));
            p.AppendChild(new Run(new TabChar()));
        }

        foreach (var r in b.Runs)
            AppendWordText(p, r.Text, bold || r.Bold, italic || r.Italic, code || r.Code, color, size);
        return p;
    }

    /// <summary>Adds text as runs, turning embedded newlines (hard breaks, code lines) into Word line breaks.</summary>
    private static void AppendWordText(Paragraph p, string text, bool bold, bool italic, bool code, string? color, int size)
    {
        var lines = text.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (i > 0) p.AppendChild(new Run(new Break()));
            if (lines[i].Length > 0) p.AppendChild(WordRun(lines[i], bold, italic, code, color, size));
        }
    }

    private static Run WordRun(string text, bool bold, bool italic, bool code, string? color, int size)
    {
        // Child order follows the OOXML schema: rFonts, b, i, color, sz.
        var rPr = new RunProperties();
        if (code) rPr.Append(new RunFonts { Ascii = "Consolas", HighAnsi = "Consolas", ComplexScript = "Consolas" });
        if (bold) rPr.Append(new Bold());
        if (italic) rPr.Append(new Italic());
        if (color is not null) rPr.Append(new Color { Val = color });
        rPr.Append(new FontSize { Val = size.ToString(CultureInfo.InvariantCulture) });
        return new Run(rPr, new Text(text) { Space = SpaceProcessingModeValues.Preserve });
    }
}
