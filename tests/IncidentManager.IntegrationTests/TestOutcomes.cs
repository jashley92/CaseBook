using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;

namespace IncidentManager.IntegrationTests;

/// <summary>HR-01: closing a case records an outcome and a closing brief; tests close with these.</summary>
internal static class TestOutcomes
{
    public static CaseService.CaseClosing Closing(string outcomeKey = CaseOutcomeCatalog.Confirmed) =>
        new(outcomeKey, "What happened on the case.", "What the team concluded.");
}
