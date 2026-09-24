using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// The structured post-incident review (lessons learned) for a case — one per case (E-26). A consistent
/// what-happened / contributing-factors / what-worked-well / opportunities-to-improve record, as standard IR
/// practice (and NYDFS 500.16's post-event review) expects, instead of leaving it to free-form notes. The
/// follow-up work it identifies is tracked as <see cref="ImprovementAction"/>s (PROD-41).
/// <para>
/// Wording is deliberately neutral and forward-looking: these records are discoverable, so the model speaks
/// of improvements rather than failures. The review is kept out of the examiner-facing case report and
/// printed only in its own lessons-learned report.
/// </para>
/// <para>
/// Audited + hash-chained like any case record. Editable after close: a review is typically written as the
/// case winds down and refined afterwards; every revision is in the audit trail.
/// </para>
/// </summary>
public class PostIncidentReview : AuditableEntity, IHashableEntity
{
    public Guid CaseId { get; set; }

    /// <summary>A factual account of what happened and why.</summary>
    public string? WhatHappened { get; set; }

    /// <summary>Conditions that contributed to the event or its impact.</summary>
    public string? ContributingFactors { get; set; }

    /// <summary>Detection and response strengths worth keeping.</summary>
    public string? WhatWorkedWell { get; set; }

    /// <summary>Opportunities to improve people, process, or technology.</summary>
    public string? OpportunitiesToImprove { get; set; }

    /// <summary>
    /// An explicit statement that the review identified no improvement actions. Distinguishes "reviewed,
    /// nothing to follow up" from "not yet looked at".
    /// </summary>
    public bool NoActionsIdentified { get; set; }

    /// <summary>True once the review has substance: what happened is recorded.</summary>
    public bool IsRecorded => !string.IsNullOrWhiteSpace(WhatHappened);

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, WhatHappened, ContributingFactors, WhatWorkedWell, OpportunitiesToImprove, NoActionsIdentified,
        CreatedBy, CreatedAtUtc.ToString("o"));
}
