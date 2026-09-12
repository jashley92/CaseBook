using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>Request to open a new case.</summary>
public sealed class CreateCaseRequest
{
    public string DescriptiveName { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;

    /// <summary>Optional analyst-chosen case number; blank auto-generates (CE-… for a Complex Event, YYYY-NN_… for a classified case).</summary>
    public string? CaseNumber { get; set; }

    /// <summary>The formal classification to open on, or <c>null</c> to file as a Complex Event (intake).</summary>
    public Classification? Classification { get; set; } = Domain.Enums.Classification.AdverseEvent;
    public Severity Severity { get; set; } = Severity.Medium;
    public CaseOrigin Origin { get; set; } = CaseOrigin.InternalDetection;
    public string? Summary { get; set; }
    public string? DetectionCaseId { get; set; }
    public string? DataTypesInvolved { get; set; }
    public string? ImpactedAssets { get; set; }

    // Third-party origin details
    public string? VendorName { get; set; }
    public string? VendorContact { get; set; }
    public string? VendorReference { get; set; }
}

/// <summary>Lightweight row for case lists and queues.</summary>
public sealed record CaseListItem(
    Guid Id,
    string CaseNumber,
    string Title,
    Classification? Classification,
    CasePhase Phase,
    Severity Severity,
    CaseOrigin Origin,
    bool IsRestricted,
    bool LegalReferred,
    bool LegalHold,
    DateTimeOffset CreatedAtUtc,
    string? IncidentCommander,
    // Lifecycle stamps carried so the list can compute the SLA status per row (E-16) without a second query.
    DateTimeOffset? DetectedAtUtc,
    DateTimeOffset? ContainedAtUtc,
    DateTimeOffset? ResolvedAtUtc);

/// <summary>Filter for listing cases.</summary>
public sealed class CaseFilter
{
    public Classification? Classification { get; set; }
    public CasePhase? Phase { get; set; }
    public Severity? MinSeverity { get; set; }
    public CaseOrigin? Origin { get; set; }
    public bool IncludeClosed { get; set; }
    public bool OnlyMine { get; set; }

    /// <summary>Only cases that have at least one overdue, still-open action item.</summary>
    public bool OverdueOnly { get; set; }

    /// <summary>Only open cases whose response-time SLA is at risk or breached (E-16).</summary>
    public bool SlaAtRiskOnly { get; set; }

    /// <summary>Only cases this user is actively assigned to (IC or Analyst). Drill-in from team workload (E-25).</summary>
    public string? AssigneeUserId { get; set; }

    /// <summary>Only cases with no active (IC/Analyst) assignee — the unassigned queue.</summary>
    public bool UnassignedOnly { get; set; }

    /// <summary>Only cases referred to Legal / Privacy (UX-10) — the SOC/IC roll-up of referral obligations.</summary>
    public bool ReferredOnly { get; set; }

    /// <summary>Only cases under a legal hold (UX-10) — the SOC/IC roll-up of preservation obligations.</summary>
    public bool OnHoldOnly { get; set; }

    /// <summary>Only cases opened (created) in this calendar month. Both must be set to apply.</summary>
    public int? OpenedYear { get; set; }
    public int? OpenedMonth { get; set; }

    /// <summary>Free text matched across case number, title, summary, entity/IOC values, and note bodies.</summary>
    public string? Search { get; set; }

    /// <summary>1-based page number.</summary>
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 25;
}

/// <summary>A page of case rows plus the total matching count, for paged list views.</summary>
public sealed record CasePage(IReadOnlyList<CaseListItem> Items, int Total, int Page, int PageSize)
{
    public int TotalPages => PageSize <= 0 ? 1 : Math.Max(1, (int)Math.Ceiling(Total / (double)PageSize));
}
