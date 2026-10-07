using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>
/// The two kinds of event step. On an internal case every step is the adversary's (the attack chain). A third-party
/// case has both: the attacker's steps in the vendor's environment, as the vendor reported them (ATT&amp;CK tactics,
/// technique, actor → target), and the disclosure milestones (when the vendor notified us, confirmed scope, confirmed
/// our data …). A vendor attack step carries ATT&amp;CK content or an actor or target; one recorded with none of those
/// is stored under the Unspecified tactic so it stays an attack step. One rule, used by the Record, the report, the
/// case's techniques, the narrative and ATT&amp;CK coverage.
/// </summary>
public static class EventSteps
{
    /// <summary>An attack step: every event step on an internal case; on a third-party case, the vendor attack steps.</summary>
    public static bool IsAttack(Case c, TimelineEntry e) => IsAttack(c.Origin, e);

    public static bool IsAttack(CaseOrigin origin, TimelineEntry e) =>
        e.Kind == TimelineKind.Event && (origin != CaseOrigin.ThirdParty || HasAttackContent(e));

    /// <summary>A disclosure milestone: a third-party case's event step that isn't an attack step.</summary>
    public static bool IsDisclosure(Case c, TimelineEntry e) =>
        e.Kind == TimelineKind.Event && c.Origin == CaseOrigin.ThirdParty && !HasAttackContent(e);

    /// <summary>ATT&amp;CK tactics (the Unspecified one included), a technique, or an actor or target.</summary>
    public static bool HasAttackContent(TimelineEntry e) =>
        e.Tactics.Count > 0 || !string.IsNullOrWhiteSpace(e.TechniqueId) || e.ActorEntityId is not null || e.TargetEntityId is not null;
}
