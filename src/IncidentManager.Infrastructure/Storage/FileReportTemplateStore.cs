using IncidentManager.Application.Reporting;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Storage;

public sealed class ReportTemplateOptions
{
    public string RootPath { get; set; } = "App_Data/report-templates";
}

/// <summary>
/// PROD-47: file-backed <see cref="IReportTemplateStore"/> — one .docx per report profile under the template root,
/// named by the profile id, mirroring the report-logo store.
/// </summary>
public sealed class FileReportTemplateStore : IReportTemplateStore
{
    private readonly string _root;

    public FileReportTemplateStore(IOptions<ReportTemplateOptions> options)
    {
        _root = Path.GetFullPath(options.Value.RootPath);
        Directory.CreateDirectory(_root);
    }

    private string PathFor(Guid profileId) => Path.Combine(_root, $"{profileId:N}.docx");

    public Task SaveAsync(Guid profileId, byte[] docx, CancellationToken ct = default) =>
        File.WriteAllBytesAsync(PathFor(profileId), docx, ct);

    public async Task<byte[]?> GetAsync(Guid profileId, CancellationToken ct = default)
    {
        var path = PathFor(profileId);
        return File.Exists(path) ? await File.ReadAllBytesAsync(path, ct) : null;
    }

    public Task DeleteAsync(Guid profileId, CancellationToken ct = default)
    {
        var path = PathFor(profileId);
        if (File.Exists(path)) File.Delete(path);
        return Task.CompletedTask;
    }
}
