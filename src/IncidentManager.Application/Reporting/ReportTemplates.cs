namespace IncidentManager.Application.Reporting;

/// <summary>
/// PROD-47: the result of checking an uploaded Word template — what it uses, and anything that rules it out.
/// BUG-151: <see cref="FillProblems"/> are the problems among <see cref="Problems"/> that only stop a report filling
/// correctly (no <c>{{report.tlp}}</c>, a field Word split): an upload is refused for them, but a template stored before
/// v1.5.2 may have them, so a config bundle still imports it (generation refuses an unmarked one).
/// </summary>
public sealed record TemplateCheck(IReadOnlyList<string> Problems, IReadOnlyList<string> Placeholders,
    IReadOnlyList<string>? FillProblems = null)
{
    public bool Ok => Problems.Count == 0;

    /// <summary>Nothing unsafe in it (macros, embedded objects, external content, unreadable, unknown fields).</summary>
    public bool Safe => Problems.All(p => FillProblems?.Contains(p) == true);
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

    /// <summary>The finished .docx for this report. A <paramref name="banner"/> (used for previews) is inserted as the
    /// document's first paragraph, so a preview can't pass for a stored report.</summary>
    byte[] Render(byte[] template, CaseReportModel model, string? banner = null);

    /// <summary>A starter template using the main placeholders, for admins to restyle.</summary>
    byte[] Starter();

    /// <summary>A starter for lessons-learned reports: the review and improvement-action fields.</summary>
    byte[] LessonsStarter();
}

/// <summary>PROD-47: where uploaded templates live (one file per library template, keyed by its id), off the
/// database like the report logo.</summary>
public interface IReportTemplateStore
{
    Task SaveAsync(Guid templateId, byte[] docx, CancellationToken ct = default);
    Task<byte[]?> GetAsync(Guid templateId, CancellationToken ct = default);
    Task DeleteAsync(Guid templateId, CancellationToken ct = default);
}
