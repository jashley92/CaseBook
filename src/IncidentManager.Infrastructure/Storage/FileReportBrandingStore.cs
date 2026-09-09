using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Storage;

public sealed class ReportBrandingOptions
{
    public string RootPath { get; set; } = "App_Data/branding";
}

/// <summary>
/// File-backed <see cref="IReportBrandingStore"/>: one logo image on disk under the branding root. Stored
/// as <c>logo.png</c> or <c>logo.jpg</c> (only one exists at a time — saving a new one clears the other),
/// mirroring the on-disk approach of the evidence and report stores.
/// </summary>
public sealed class FileReportBrandingStore : IReportBrandingStore
{
    private readonly string _root;
    private static readonly string[] KnownFiles = ["logo.png", "logo.jpg"];

    public FileReportBrandingStore(IOptions<ReportBrandingOptions> options)
    {
        _root = Path.GetFullPath(options.Value.RootPath);
        Directory.CreateDirectory(_root);
    }

    public async Task<ReportLogo?> GetLogoAsync(CancellationToken ct = default)
    {
        foreach (var name in KnownFiles)
        {
            var path = Path.Combine(_root, name);
            if (!File.Exists(path)) continue;
            var bytes = await File.ReadAllBytesAsync(path, ct);
            var type = name.EndsWith(".png", StringComparison.OrdinalIgnoreCase) ? "image/png" : "image/jpeg";
            return new ReportLogo(bytes, type);
        }
        return null;
    }

    public async Task SaveLogoAsync(byte[] bytes, string contentType, CancellationToken ct = default)
    {
        var isPng = contentType.Contains("png", StringComparison.OrdinalIgnoreCase);
        var isJpeg = contentType.Contains("jpeg", StringComparison.OrdinalIgnoreCase)
                     || contentType.Contains("jpg", StringComparison.OrdinalIgnoreCase);
        if (!isPng && !isJpeg)
            throw new ArgumentException("Logo must be a PNG or JPEG image.", nameof(contentType));

        // Only one logo file exists at a time; clear the other format first.
        Clear();
        var target = Path.Combine(_root, isPng ? "logo.png" : "logo.jpg");
        await File.WriteAllBytesAsync(target, bytes, ct);
    }

    public Task ClearLogoAsync(CancellationToken ct = default)
    {
        Clear();
        return Task.CompletedTask;
    }

    private void Clear()
    {
        foreach (var name in KnownFiles)
        {
            var path = Path.Combine(_root, name);
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
