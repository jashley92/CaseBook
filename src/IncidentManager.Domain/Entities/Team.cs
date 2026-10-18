using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// CAP-36: a team that owns cases, for routing and filtering only. Admin-managed reference data like
/// <see cref="CaseOutcome"/>: a case stores the team's id (<see cref="Case.TeamId"/>), the URL filter, saved views and the
/// configuration bundle name it by its stable <see cref="Key"/> (generated once, never changed or reused), and the name,
/// detection-source label and link template are editable. A team never decides who can see a case: visibility stays the
/// single need-to-know filter (ADR 0003). Teams are retired, never deleted, so a case that names one always resolves.
/// The team's chat webhook URL is a secret, kept encrypted outside this row (CAP-40's StoredSecrets), and so never in the
/// row hash, the audit trail or the configuration bundle.
/// </summary>
public class Team : AuditableEntity, IHashableEntity
{
    public const int KeyMax = 40;
    public const int NameMax = 100;
    public const int LabelMax = 60;
    public const int LinkTemplateMax = 500;

    /// <summary>Stable machine key (e.g. "SocTier1"): what the URL filter, saved views and the bundle name. Never changed.</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Display name, unique ignoring case.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Active teams are offered when filing and editing a case; a retired one stays on the cases that name it.</summary>
    public bool IsActive { get; set; } = true;

    /// <summary>The team's detection system, shown in place of <c>ExternalLinks:DetectionSourceLabel</c> on its cases. Null: the global one.</summary>
    public string? DetectionSourceLabel { get; set; }

    /// <summary>The team's detection case link, in place of <c>ExternalLinks:DetectionCaseUrlTemplate</c> on its cases
    /// (<c>{0}</c> marks where the detection case id goes, as there). Null: the global one.</summary>
    public string? DetectionLinkTemplate { get; set; }

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        Key, Canonical.Text(Name), IsActive, Canonical.Text(DetectionSourceLabel), Canonical.Text(DetectionLinkTemplate),
        CreatedBy, CreatedAtUtc.ToString("o"));
}

/// <summary>
/// CAP-36: a person in a team. Membership routes and scopes convenience state only (a view shared with the team, the team
/// a new case defaults to); it never grants or narrows access to a case. Audited and hash-chained like the team.
/// </summary>
public class TeamMember : Entity, IHashableEntity
{
    public Guid TeamId { get; set; }

    /// <summary>The member's user id, as the user directory holds it.</summary>
    public string UserId { get; set; } = string.Empty;

    public DateTimeOffset AddedAtUtc { get; set; }
    public string AddedBy { get; set; } = string.Empty;

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        TeamId, Canonical.Text(UserId), AddedAtUtc.ToString("o"), Canonical.Text(AddedBy));
}
