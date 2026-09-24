using System.Globalization;
using System.Text;
using Markdig;
using Markdig.Syntax;
using Markdig.Syntax.Inlines;

namespace IncidentManager.Application.Content;

/// <summary>What a block of report prose is: the Markdown constructs the editor toolbar can produce.</summary>
public enum RichBlockKind { Paragraph, Heading, Bullet, Numbered, Quote, Code }

/// <summary>A run of text sharing one style. <see cref="Code"/> is monospace.</summary>
public sealed record RichRun(string Text, bool Bold = false, bool Italic = false, bool Code = false);

/// <summary>
/// One block of formatted prose. <see cref="Level"/> is the heading level (1–6) for a heading, or the nesting
/// depth (0 = top) for list items and paragraphs continuing a list item; <see cref="Marker"/> is the list
/// marker to print ("•", "3.").
/// </summary>
public sealed record RichBlock(RichBlockKind Kind, IReadOnlyList<RichRun> Runs, int Level = 0, string? Marker = null)
{
    public string PlainText => string.Concat(Runs.Select(r => r.Text));
}

/// <summary>
/// Turns analyst Markdown into a format-neutral list of <see cref="RichBlock"/>s, so the Word and PDF report
/// renderers (and the in-app report preview) print headings, bold/italic, lists, quotes and code the same way,
/// from one interpretation of the text. Links print their text (plus the URL when it differs); entity tags print
/// their label. Raw HTML stays disabled, exactly as on screen.
/// </summary>
public static class RichText
{
    private static readonly string[] Bullets = ["•", "◦", "▪"];

    public static IReadOnlyList<RichBlock> Parse(string? markdown)
    {
        var blocks = new List<RichBlock>();
        if (string.IsNullOrWhiteSpace(markdown)) return blocks;
        foreach (var block in Markdown.Parse(markdown, MarkdownService.Pipeline))
            AddBlock(blocks, block, depth: 0, quote: false);
        return blocks;
    }

    /// <summary>
    /// Plain text for places that can't carry styling (table cells, CSV): list markers and line breaks are kept
    /// (one block per line, nested items indented), emphasis is dropped.
    /// </summary>
    public static string ToText(string? markdown) =>
        string.Join("\n", Parse(markdown).Select(b => b.Kind switch
        {
            RichBlockKind.Bullet or RichBlockKind.Numbered => new string(' ', b.Level * 2) + b.Marker + " " + b.PlainText,
            RichBlockKind.Paragraph when b.Level > 0 => new string(' ', b.Level * 2) + b.PlainText,
            _ => b.PlainText
        }));

    private static void AddBlock(List<RichBlock> blocks, Block block, int depth, bool quote)
    {
        switch (block)
        {
            case HeadingBlock h:
                blocks.Add(new RichBlock(RichBlockKind.Heading, Runs(h.Inline), Math.Clamp(h.Level, 1, 6)));
                break;

            case ParagraphBlock p:
                blocks.Add(new RichBlock(quote ? RichBlockKind.Quote : RichBlockKind.Paragraph, Runs(p.Inline), depth));
                break;

            case ListBlock list:
                var number = list.IsOrdered && int.TryParse(list.OrderedStart, NumberStyles.Integer, CultureInfo.InvariantCulture, out var start) ? start : 1;
                foreach (var item in list.OfType<ListItemBlock>())
                {
                    var marker = list.IsOrdered ? $"{number++}." : Bullets[Math.Min(depth, Bullets.Length - 1)];
                    var first = true;
                    foreach (var child in item)
                    {
                        // The item's first paragraph carries the marker; anything after it (a second paragraph, a
                        // nested list) continues underneath at the next depth.
                        if (first && child is ParagraphBlock para)
                            blocks.Add(new RichBlock(list.IsOrdered ? RichBlockKind.Numbered : RichBlockKind.Bullet,
                                Runs(para.Inline), depth, marker));
                        else if (first)
                        {
                            blocks.Add(new RichBlock(list.IsOrdered ? RichBlockKind.Numbered : RichBlockKind.Bullet, [], depth, marker));
                            AddBlock(blocks, child, depth + 1, quote);
                        }
                        else
                            AddBlock(blocks, child, depth + 1, quote);
                        first = false;
                    }
                }
                break;

            case QuoteBlock q:
                foreach (var child in q) AddBlock(blocks, child, depth, quote: true);
                break;

            case CodeBlock code:   // fenced and indented
                var text = string.Join("\n", code.Lines.Lines.Take(code.Lines.Count).Select(l => l.ToString()));
                blocks.Add(new RichBlock(RichBlockKind.Code, [new RichRun(text, Code: true)], depth));
                break;

            case ContainerBlock container:
                foreach (var child in container) AddBlock(blocks, child, depth, quote);
                break;

            // Thematic breaks and anything else carry no printable text.
        }
    }

    private static List<RichRun> Runs(ContainerInline? inline)
    {
        var runs = new List<RichRun>();
        if (inline is not null) AddInlines(runs, inline, bold: false, italic: false);
        return Merge(runs);
    }

    private static void AddInlines(List<RichRun> runs, ContainerInline container, bool bold, bool italic)
    {
        foreach (var inline in container)
        {
            switch (inline)
            {
                case LiteralInline lit:
                    runs.Add(new RichRun(lit.Content.ToString(), bold, italic));
                    break;
                case EmphasisInline em:
                    var strong = em.DelimiterCount >= 2;
                    AddInlines(runs, em, bold || strong, italic || !strong);
                    break;
                case CodeInline code:
                    runs.Add(new RichRun(code.Content, bold, italic, Code: true));
                    break;
                case LineBreakInline br:
                    runs.Add(new RichRun(br.IsHard ? "\n" : " ", bold, italic));
                    break;
                case AutolinkInline auto:
                    runs.Add(new RichRun(auto.Url, bold, italic));
                    break;
                case LinkInline link:
                    var before = runs.Count;
                    AddInlines(runs, link, bold, italic);
                    var label = string.Concat(runs.Skip(before).Select(r => r.Text));
                    // Print a real link's URL after its text so the document stays useful on paper; entity tags
                    // (entity:<guid>) and bare links (text == URL) print just the label.
                    if (link.Url is { Length: > 0 } url && !link.IsImage
                        && !url.StartsWith("entity:", StringComparison.OrdinalIgnoreCase) && url != label)
                        runs.Add(new RichRun($" ({url})", bold, italic));
                    break;
                case HtmlEntityInline entity:
                    runs.Add(new RichRun(entity.Transcoded.ToString(), bold, italic));
                    break;
                case ContainerInline nested:
                    AddInlines(runs, nested, bold, italic);
                    break;
            }
        }
    }

    // Adjacent runs with the same style collapse into one (fewer, cleaner document runs).
    private static List<RichRun> Merge(List<RichRun> runs)
    {
        var merged = new List<RichRun>();
        var sb = new StringBuilder();
        RichRun? style = null;
        foreach (var r in runs.Where(r => r.Text.Length > 0))
        {
            if (style is not null && (style.Bold, style.Italic, style.Code) != (r.Bold, r.Italic, r.Code))
            {
                merged.Add(style with { Text = sb.ToString() });
                sb.Clear();
            }
            style = r;
            sb.Append(r.Text);
        }
        if (style is not null) merged.Add(style with { Text = sb.ToString() });
        return merged;
    }
}
