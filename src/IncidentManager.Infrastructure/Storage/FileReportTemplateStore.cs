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
        var staged = await StageAsync(templateId, docx, ct);
        await CommitAsync(staged, ct);
    }

    // BUG-199: written to a file of its own, then moved over the live one (a rename, so a reader gets the old file or the
    // new, never a part-written one).
    public async Task<StagedTemplate> StageAsync(Guid templateId, byte[] docx, CancellationToken ct = default)
    {
        Directory.CreateDirectory(_root);
        var aside = Path.Combine(_root, $"{templateId:N}.{Guid.NewGuid():N}.staged");
        try { await File.WriteAllBytesAsync(aside, docx, ct); }
        catch
        {
            File.Delete(aside);
            throw;
        }
        return new StagedTemplate(templateId, aside);
    }

    // BUG-239: a report job or preview reading the live file can hold it for a moment, which makes the move fail on
    // Windows; a few short retries ride that out. A lasting failure (read-only, no permission) still throws.
    public async Task CommitAsync(StagedTemplate staged, CancellationToken ct = default)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                File.Move(staged.Token, PathFor(staged.TemplateId), overwrite: true);
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException && attempt < 5)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(200 * attempt), ct);
            }
        }
    }

    public Task DiscardAsync(StagedTemplate staged)
    {
        File.Delete(staged.Token);
        return Task.CompletedTask;
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
