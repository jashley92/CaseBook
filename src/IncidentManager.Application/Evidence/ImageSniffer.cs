namespace IncidentManager.Application.Evidence;

/// <summary>
/// Content-based raster-image detection for the inline evidence endpoint (S-04). The inline path renders
/// bytes <b>in the browser</b> (no attachment disposition), so it must trust the actual bytes, not the
/// client-supplied Content-Type stored at upload. It recognises only genuine raster images (PNG, JPEG,
/// GIF, WEBP) by magic number — an active format such as SVG, or a mislabeled non-image file, is not
/// recognised and is refused, so stored content can never ride this endpoint as script even if the CSP
/// were relaxed.
/// </summary>
public static class ImageSniffer
{
    /// <summary>
    /// Returns the canonical raster-image content-type for <paramref name="header"/> (a file's leading
    /// bytes — 12 are enough for every type below), or <c>null</c> if the bytes are not a recognised
    /// raster image. SVG and non-image content deliberately return <c>null</c>.
    /// </summary>
    public static string? RasterContentType(ReadOnlySpan<byte> header)
    {
        // PNG: 89 50 4E 47 0D 0A 1A 0A
        if (header.Length >= 8 &&
            header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47 &&
            header[4] == 0x0D && header[5] == 0x0A && header[6] == 0x1A && header[7] == 0x0A)
            return "image/png";

        // JPEG: FF D8 FF
        if (header.Length >= 3 && header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF)
            return "image/jpeg";

        // GIF: "GIF87a" or "GIF89a"
        if (header.Length >= 6 &&
            header[0] == (byte)'G' && header[1] == (byte)'I' && header[2] == (byte)'F' && header[3] == (byte)'8' &&
            (header[4] == (byte)'7' || header[4] == (byte)'9') && header[5] == (byte)'a')
            return "image/gif";

        // WEBP: "RIFF" <4-byte size> "WEBP"
        if (header.Length >= 12 &&
            header[0] == (byte)'R' && header[1] == (byte)'I' && header[2] == (byte)'F' && header[3] == (byte)'F' &&
            header[8] == (byte)'W' && header[9] == (byte)'E' && header[10] == (byte)'B' && header[11] == (byte)'P')
            return "image/webp";

        return null;
    }
}
