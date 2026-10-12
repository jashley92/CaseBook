using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Reporting;

/// <summary>
/// BUG-141: a report is marked at least as restrictively as anything in it. An indicator marked TLP:RED appears in the
/// relationships appendix, the entity graph and the attack chain as well as the IOC table, so a GREEN report holding it
/// would carry RED content under a GREEN marking. The marking chosen is raised to the most restrictive entity's.
/// </summary>
public static class ReportMarking
{
    /// <summary>The most restrictive TLP on the case's entities, if any is marked.</summary>
    public static TlpLevel? MostRestrictive(Case c) => c.Entities.Where(e => e.Tlp is not null).Max(e => e.Tlp);

    /// <summary>The marking a report gets: the one chosen, or the content's when that's more restrictive.</summary>
    public static TlpLevel Effective(TlpLevel chosen, TlpLevel? content) => content is { } m && m > chosen ? m : chosen;
}
