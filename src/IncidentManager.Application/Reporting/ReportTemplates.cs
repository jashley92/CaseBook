namespace IncidentManager.Application.Reporting;

/// <summary>PROD-47: the result of checking an uploaded Word template — what it uses, and anything that rules it out.</summary>
public sealed record TemplateCheck(IReadOnlyList<string> Problems, IReadOnlyList<string> Placeholders)
{
    public bool Ok => Problems.Count == 0;
}

/// <summary>
/// PROD-47: fills a customer-designed Word (.docx) template from the report model, and checks templates on upload.
/// Placeholders are listed in <see cref="ReportTemplateFields"/>.
/// </summary>
public interface IReportTemplateEngine
{
    /// <summary>Checks a template: a plain Word document (no macros, embedded objects or externally loaded content)
    /// using only known placeholders.</summary>
    TemplateCheck Check(byte[] docx);

    /// <summary>The finished .docx for this report.</summary>
    byte[] Render(byte[] template, CaseReportModel model);

    /// <summary>A starter template using the main placeholders, for admins to restyle.</summary>
    byte[] Starter();
}

/// <summary>PROD-47: where uploaded templates live (one per report profile), off the database like the report logo.</summary>
public interface IReportTemplateStore
{
    Task SaveAsync(Guid profileId, byte[] docx, CancellationToken ct = default);
    Task<byte[]?> GetAsync(Guid profileId, CancellationToken ct = default);
    Task DeleteAsync(Guid profileId, CancellationToken ct = default);
}
