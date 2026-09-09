using IncidentManager.Application.Sla;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// A no-target SLA provider for tests that don't exercise E-16 flags — case listing/creation behaves
/// exactly as before (no case is flagged at-risk). Tests that assert on SLA can pass their own targets.
/// </summary>
internal sealed class TestSlaTargets : ISlaTargetsProvider
{
    public SlaTargets Current { get; }

    public TestSlaTargets(SlaTargets? targets = null) => Current = targets ?? SlaTargets.Empty;
}
