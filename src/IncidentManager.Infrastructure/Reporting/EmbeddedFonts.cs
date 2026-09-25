namespace IncidentManager.Infrastructure.Reporting;

/// <summary>
/// The bundled DejaVu Sans faces (embedded in this assembly), so the report diagrams render identically on
/// Windows, Linux (CI) and Windows Server Core without depending on fonts installed on the host.
/// </summary>
public static class EmbeddedFonts
{
    /// <summary>The embedded TTF bytes for a face file name, e.g. "DejaVuSans.ttf".</summary>
    public static byte[] Get(string faceName)
    {
        var asm = typeof(EmbeddedFonts).Assembly;
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
