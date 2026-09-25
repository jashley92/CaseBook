using IncidentManager.Application.Reporting;

namespace IncidentManager.Application.Abstractions;

/// <summary>Renders a case report to Word bytes (the built-in layout; templates go through IReportTemplateEngine).</summary>
public interface IReportGenerator
{
    byte[] GenerateWord(CaseReportModel model);
}
