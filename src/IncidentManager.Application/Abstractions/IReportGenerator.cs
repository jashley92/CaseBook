using IncidentManager.Application.Reporting;

namespace IncidentManager.Application.Abstractions;

/// <summary>Renders a case report to Word (working draft) or PDF (final) bytes.</summary>
public interface IReportGenerator
{
    byte[] GenerateWord(CaseReportModel model);
    byte[] GeneratePdf(CaseReportModel model);
}
