using Markdig;
using Markdig.Renderers;
using Markdig.Syntax;
using Markdig.Syntax.Inlines;

namespace IncidentManager.Application.Content;

/// <summary>
/// Renders analyst-authored Markdown (used by the Investigation timeline) to safe HTML for display and
/// to plain text for reports. Storage stays Markdown (human-readable, hash-clean); rendering happens at
/// the edges. Raw HTML is disabled and dangerous link schemes are neutralised, so stored content cannot
/// inject script — the app's strict CSP (`script-src 'self'`) is a second line of defence.
/// </summary>
public interface IMarkdownService
{
    /// <summary>Renders Markdown to sanitised HTML (raw HTML escaped, unsafe link schemes dropped).</summary>
    string ToHtml(string? markdown);

    /// <summary>Renders Markdown to readable plain text (formatting stripped) for Word/PDF reports.</summary>
    string ToPlainText(string? markdown);
}

public sealed class MarkdownService : IMarkdownService
{
    // DisableHtml: any raw HTML the analyst types is emitted as escaped text, not live markup.
    private static readonly MarkdownPipeline Pipeline = new MarkdownPipelineBuilder()
        .DisableHtml()
        .UseAutoLinks()
        .Build();

    // Only these URL schemes are allowed on links; everything else (javascript:, data:, vbscript:, file:)
    // is rewritten to an inert anchor so stored Markdown cannot carry an executable payload.
    private static readonly string[] AllowedSchemes = { "http://", "https://", "mailto:", "ftp://" };

    public string ToHtml(string? markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown)) return string.Empty;

        var document = Markdown.Parse(markdown, Pipeline);
        foreach (var link in document.Descendants<LinkInline>())
        {
            if (!IsSafeUrl(link.Url))
                link.Url = "#";
        }

        using var writer = new StringWriter();
        var renderer = new HtmlRenderer(writer);
        Pipeline.Setup(renderer);
        renderer.Render(document);
        writer.Flush();
        return writer.ToString();
    }

    public string ToPlainText(string? markdown)
        => string.IsNullOrWhiteSpace(markdown) ? string.Empty : Markdown.ToPlainText(markdown, Pipeline);

    private static bool IsSafeUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return true;   // empty/relative anchors are fine
        var u = url.TrimStart();

        // A relative link or in-page fragment has no scheme — allow it.
        if (u.StartsWith('/') || u.StartsWith('#') || u.StartsWith('.')) return true;
        if (!u.Contains(':')) return true;

        foreach (var scheme in AllowedSchemes)
        {
            if (u.StartsWith(scheme, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
}
