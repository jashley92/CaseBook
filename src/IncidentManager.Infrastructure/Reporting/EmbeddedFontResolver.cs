using PdfSharp.Fonts;

namespace IncidentManager.Infrastructure.Reporting;

/// <summary>
/// Serves the bundled DejaVu Sans faces (embedded in this assembly) for every font request, so PDF
/// report generation is fully self-contained and does not depend on fonts installed on the host OS.
/// This lets the reports render identically on Windows, Linux (CI), and Windows Server Core.
/// </summary>
public sealed class EmbeddedFontResolver : IFontResolver
{
    private const string Regular = "DejaVuSans.ttf";
    private const string Bold = "DejaVuSans-Bold.ttf";
    private const string Italic = "DejaVuSans-Oblique.ttf";
    private const string BoldItalic = "DejaVuSans-BoldOblique.ttf";

    /// <summary>Routes any requested family to the bundled DejaVu Sans face for the given style.</summary>
    public FontResolverInfo ResolveTypeface(string familyName, bool bold, bool italic)
    {
        var face = (bold, italic) switch
        {
            (true, true) => BoldItalic,
            (true, false) => Bold,
            (false, true) => Italic,
            _ => Regular
        };
        return new FontResolverInfo(face);
    }

    /// <summary>Returns the embedded TTF bytes for a face resolved by <see cref="ResolveTypeface"/>.</summary>
    public byte[] GetFont(string faceName)
    {
        var asm = typeof(EmbeddedFontResolver).Assembly;
        var resourceName = Array.Find(asm.GetManifestResourceNames(),
                               n => n.EndsWith(faceName, StringComparison.Ordinal))
                           ?? throw new InvalidOperationException($"Embedded font resource '{faceName}' was not found.");

        using var stream = asm.GetManifestResourceStream(resourceName)
                           ?? throw new InvalidOperationException($"Could not open embedded font '{resourceName}'.");
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }
}
