using IncidentManager.Application.Reporting;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Storage;

public sealed class ReportTemplateOptions
{
    /// <summary>
    /// Where templates are kept. Blank = a <c>report-templates</c> folder beside the report-logo store
    /// (<c>ReportBranding:RootPath</c>) — on production that's the ACL'd data root, so a server upgraded from a
    /// release without this setting (the upgrade never rewrites appsettings.Production.json) still keeps templates
    /// off the read-only web root, where the next upgrade's mirror copy would also delete them.
    /// </summary>
    public string? RootPath { get; set; }
}

/// <summary>
/// PROD-47: file-backed <see cref="IReportTemplateStore"/> — one .docx per library template under the template root,
/// named by the template id (templates migrated from a profile kept that profile's id, so their files didn't move), mirroring the report-logo store.
/// </summary>
public sealed class FileReportTemplateStore : IReportTemplateStore
{
    private readonly string _root;

    public FileReportTemplateStore(IOptions<ReportTemplateOptions> options, IOptions<ReportBrandingOptions> branding)
    {
        _root = Path.GetFullPath(ResolveRoot(options.Value.RootPath, branding.Value.RootPath));
        // Created on first upload, not here: a missing or unwritable folder must never stop the app starting.
    }

    /// <summary>The configured root, else a sibling of the branding root (see <see cref="ReportTemplateOptions.RootPath"/>).</summary>
    public static string ResolveRoot(string? configured, string brandingRoot)
    {
        if (!string.IsNullOrWhiteSpace(configured)) return configured;
        var parent = Path.GetDirectoryName(Path.GetFullPath(brandingRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        return Path.Combine(parent ?? AppContext.BaseDirectory, "report-templates");
    }

    private string PathFor(Guid templateId) => Path.Combine(_root, $"{templateId:N}.docx");

    public async Task SaveAsync(Guid templateId, byte[] docx, CancellationToken ct = default)
    {
        Directory.CreateDirectory(_root);
        await File.WriteAllBytesAsync(PathFor(templateId), docx, ct);
    }

    public async Task<byte[]?> GetAsync(Guid templateId, CancellationToken ct = default)
    {
        var path = PathFor(templateId);
        return File.Exists(path) ? await File.ReadAllBytesAsync(path, ct) : null;
    }

    public Task DeleteAsync(Guid templateId, CancellationToken ct = default)
    {
        var path = PathFor(templateId);
        if (File.Exists(path)) File.Delete(path);
        return Task.CompletedTask;
    }
}
