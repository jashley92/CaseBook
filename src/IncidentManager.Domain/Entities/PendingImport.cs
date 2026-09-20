using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// PROD-33: a case-import document submitted programmatically (e.g. by an XSIAM/SOAR playbook over the
/// import API) that is waiting for a human to review and confirm it into a case. This is the staging record
/// that preserves the human gate — nothing the API sends mutates case state until a person applies it here.
///
/// Workflow/staging state, deliberately NOT audited or hash-chained (see the interceptor's NotAudited set):
/// the submission is recorded by its own fields, and the case writes made when it is <b>applied</b> go
/// through the audited <c>CaseService</c> path like any other edit.
/// </summary>
public class PendingImport : Entity
{
    /// <summary>The authenticated principal that submitted the document (the API caller / service account).</summary>
    public string SubmittedBy { get; set; } = "";
    public DateTimeOffset SubmittedAtUtc { get; set; }

    /// <summary>Provenance the document declared (its <c>origin</c>), for the queue at a glance.</summary>
    public string? Origin { get; set; }

    /// <summary>A short human-readable label for the queue (target + item counts).</summary>
    public string Summary { get; set; } = "";

    /// <summary>The raw submitted JSON, re-parsed and previewed when a human opens it to confirm.</summary>
    public string RawJson { get; set; } = "";

    /// <summary>The existing case the document targeted, if any (a hint; the reviewer can still change it).</summary>
    public Guid? TargetCaseId { get; set; }

    public PendingImportStatus Status { get; set; } = PendingImportStatus.Pending;

    // Decision record (set when applied or rejected).
    public string? DecidedBy { get; set; }
    public DateTimeOffset? DecidedAtUtc { get; set; }
    public string? DecisionNote { get; set; }

    /// <summary>The case the import was applied into (set on <see cref="PendingImportStatus.Applied"/>).</summary>
    public Guid? ResolvedCaseId { get; set; }
    public string? ResolvedCaseNumber { get; set; }
}
