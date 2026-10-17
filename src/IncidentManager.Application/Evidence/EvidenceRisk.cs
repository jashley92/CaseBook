namespace IncidentManager.Application.Evidence;

/// <summary>PROD-58: when the Evidence tab offers the password-protected zip as a file's main download.</summary>
public enum SafeDownloadMode
{
    /// <summary>For files that can run or carry something that runs (the default).</summary>
    RiskyTypes,
    /// <summary>For every file.</summary>
    Always,
    /// <summary>Never as the main download (the zip is still offered beside it).</summary>
    Off,
}

/// <summary>
/// PROD-58: whether a piece of evidence is a file that can run, or carry something that runs, when opened on an
/// analyst's computer: by its name, the type it was uploaded as, and (where read) its first bytes. Such files download
/// by default inside a zip with the password "infected", the security field's convention, so a double-click can't run
/// one and the analyst's antivirus doesn't delete it on arrival. One function for the Evidence tab's buttons and the
/// endpoints (C2). A file renamed to look harmless and uploaded with a harmless type is caught only by its bytes, so
/// administrators who want every file wrapped choose <see cref="SafeDownloadMode.Always"/>.
/// </summary>
public static class EvidenceRisk
{
    // Programs, scripts, shortcuts and installers; disk images that mount and autorun; Office files with macros; pages
    // that run script when opened from disk.
    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".drv", ".ocx", ".msi", ".msp", ".msc", ".mst",
        ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".mjs", ".wsf", ".wsh", ".wsc", ".hta",
        ".lnk", ".url", ".scf", ".reg", ".inf", ".chm", ".xll", ".gadget", ".appx", ".appxbundle", ".msix", ".application",
        ".iso", ".img", ".vhd", ".vhdx",
        ".jar", ".apk", ".app", ".dmg", ".pkg", ".sh", ".bash", ".py", ".pyw", ".pl", ".rb", ".elf", ".so", ".dylib",
        ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".ppsm", ".sldm", ".one",
        ".html", ".htm", ".xhtml", ".svg", ".mht", ".mhtml",
    };

    private static readonly HashSet<string> Types = new(StringComparer.OrdinalIgnoreCase)
    {
        "application/x-msdownload", "application/x-dosexec", "application/x-msdos-program", "application/x-ms-installer",
        "application/vnd.microsoft.portable-executable", "application/x-executable", "application/x-elf",
        "application/x-mach-binary", "application/java-archive", "application/vnd.android.package-archive",
        "application/x-ms-shortcut", "application/hta", "application/x-sh", "application/x-bat", "text/html",
        "application/xhtml+xml", "image/svg+xml", "application/javascript", "text/javascript", "application/x-iso9660-image",
    };

    /// <summary>Whether the file can run, or carry something that runs, by any of what's known about it.</summary>
    public static bool IsRisky(string? fileName, string? contentType, ReadOnlySpan<byte> header = default) =>
        Reason(fileName, contentType, header) is not null;

    /// <summary>Why it's treated as risky, for the Evidence tab's note; null when it isn't.</summary>
    public static string? Reason(string? fileName, string? contentType, ReadOnlySpan<byte> header = default)
    {
        if (ByHeader(header) is { } what) return what;
        var ext = Path.GetExtension(fileName ?? "");
        if (ext.Length > 0 && Extensions.Contains(ext.TrimEnd('.', ' '))) return $"a {ext.ToLowerInvariant()} file can run on your computer";
        var type = (contentType ?? "").Split(';')[0].Trim();
        if (type.Contains("macroenabled", StringComparison.OrdinalIgnoreCase)) return "an Office file with macros can run code";
        if (Types.Contains(type)) return "a file of this type can run on your computer";
        return null;
    }

    private static string? ByHeader(ReadOnlySpan<byte> h)
    {
        if (h.Length >= 2 && h[0] == (byte)'M' && h[1] == (byte)'Z') return "it's a Windows program";
        if (h.Length >= 4 && h[0] == 0x7F && h[1] == (byte)'E' && h[2] == (byte)'L' && h[3] == (byte)'F') return "it's a Linux program";
        if (h.Length >= 4)
        {
            var magic = (uint)(h[0] << 24 | h[1] << 16 | h[2] << 8 | h[3]);
            if (magic is 0xFEEDFACE or 0xFEEDFACF or 0xCEFAEDFE or 0xCFFAEDFE or 0xCAFEBABE) return "it's a macOS program";
        }
        // An OLE compound file: a legacy Office document or an Outlook message, which can carry macros or attachments.
        if (h.StartsWith(OleMagic))
            return "a legacy Office or Outlook file can carry macros or attachments";
        return null;
    }

    /// <summary>The reason as a sentence, for a tooltip or a message: "It's a Windows program."</summary>
    public static string? Sentence(string? fileName, string? contentType, ReadOnlySpan<byte> header = default) =>
        Reason(fileName, contentType, header) is { } r ? char.ToUpperInvariant(r[0]) + r[1..] + "." : null;

    private static readonly byte[] OleMagic = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    /// <summary>Whether the zip is the main download for this file under <paramref name="mode"/>.</summary>
    public static bool ZipFirst(SafeDownloadMode mode, string? fileName, string? contentType) => mode switch
    {
        SafeDownloadMode.Always => true,
        SafeDownloadMode.Off => false,
        _ => IsRisky(fileName, contentType),
    };

    /// <summary>The name inside the zip: the file's own name with any folder, control or reserved character removed (C13),
    /// so an unzip tool can't be steered outside the folder it extracts to.</summary>
    public static string EntryName(string? fileName)
    {
        var name = (fileName ?? "").Replace('\\', '/');
        name = name[(name.LastIndexOf('/') + 1)..];
        var clean = new string(name.Where(c => c >= 0x20 && c != 0x7F && "<>:\"|?*".IndexOf(c) < 0).ToArray()).Trim(' ', '.');
        return clean.Length == 0 ? "evidence.bin" : Common.TextFit.Cap(clean, 200, marker: "")!;
    }

    /// <summary>The password every safe zip uses: the field's convention, so anyone receiving it knows it.</summary>
    public const string ZipPassword = "infected";
}
