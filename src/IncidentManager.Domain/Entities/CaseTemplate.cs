using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A curated playbook (E-06) an analyst can start a case from, or apply to an open case. It carries
/// optional <b>field defaults</b> that quick-fill the New Case form, plus an ordered set of
/// <see cref="CaseTemplateStep"/>s that are seeded as <see cref="ActionItem"/>s. Templates are admin
/// reference data — audited and hash-chained like roles/settings, but not case-scoped.
/// </summary>
public class CaseTemplate : AuditableEntity, IHashableEntity
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>Inactive templates are kept (for audit/history) but hidden from the pickers.</summary>
    public bool IsActive { get; set; } = true;

    /// <summary>Display order in the pickers (ascending); ties break on name.</summary>
    public int SortOrder { get; set; }

    // --- Field defaults (the "quick-fill" half). All optional; a null leaves the form's own default. ---
    public Classification? DefaultClassification { get; set; }
    public Severity? DefaultSeverity { get; set; }
    public string? DefaultDataTypes { get; set; }
    public string? SummaryBoilerplate { get; set; }

    /// <summary>The ordered playbook steps seeded as action items.</summary>
    public List<CaseTemplateStep> Steps { get; set; } = [];

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        Name, Description, IsActive, SortOrder,
        DefaultClassification is { } c ? ((int)c).ToString() : "",
        DefaultSeverity is { } s ? ((int)s).ToString() : "",
        DefaultDataTypes, SummaryBoilerplate, CreatedBy, CreatedAtUtc.ToString("o"));
}

/// <summary>
/// One playbook step within a <see cref="CaseTemplate"/>. When the template is applied, each selected
/// step becomes an <see cref="ActionItem"/> on the case: <see cref="Title"/>/<see cref="Description"/>
/// carried over, the owner defaulting to the case owner (the <see cref="OwnerHint"/> role wins when set),
/// and the due date computed as apply-time + <see cref="DueOffsetHours"/> (so a step applied mid-case
/// isn't instantly overdue).
/// </summary>
public class CaseTemplateStep : Entity, IHashableEntity
{
    public Guid TemplateId { get; set; }

    /// <summary>Position within the template (ascending).</summary>
    public int Order { get; set; }

    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>Optional owner hint (a role such as "SOC analyst", or a name). Overrides the case-owner
    /// default when the step is seeded. Left blank in most CaseBook deployments — steps fall to the case owner.</summary>
    public string? OwnerHint { get; set; }

    /// <summary>Hours after the template is applied by which the seeded action item is due; null = no due date.</summary>
    public int? DueOffsetHours { get; set; }

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        TemplateId, Order, Title, Description, OwnerHint,
        DueOffsetHours is { } h ? h.ToString() : "");
}
