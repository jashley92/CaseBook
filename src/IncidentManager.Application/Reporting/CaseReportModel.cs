namespace IncidentManager.Application.Reporting;

public sealed record ReportClassificationItem(DateTimeOffset AtUtc, string From, string To, string Reason, string By);
public sealed record ReportTimelineItem(DateTimeOffset OccurredAtUtc, string Type, string Description, string? Source);
public sealed record ReportEvidenceItem(string FileName, long SizeBytes, string Sha256, DateTimeOffset UploadedAtUtc, string UploadedBy);
public sealed record ReportNoteItem(DateTimeOffset AtUtc, string Author, string Body);
public sealed record ReportActionItemRow(string Title, string? Owner, DateTimeOffset? DueAtUtc, string Status);
public sealed record ReportAssignmentRow(string User, string Role);
public sealed record ReportEntityRow(string Type, string Value, string? Label, string Disposition, string? Description, string? Source);
public sealed record ReportRelationshipRow(string Source, string Relationship, string Target, string? Description);
public sealed record ReportTechniqueRow(string TechniqueId, string Name, string Tactic);

/// <summary>One ordered step of the reconstructed attack narrative (Event timeline), for the report.</summary>
public sealed record ReportAttackStep(int Order, DateTimeOffset OccurredAtUtc, string Tactics, string Actor,
    string Target, string? TechniqueId, string Description);

/// <summary>Flat, presentation-ready projection of a case used by both the Word and PDF generators.</summary>
public sealed class CaseReportModel
{
    // Deployment branding for the header (out of source; set in the admin console).
    public string? OrganizationName { get; init; }
    public string? TeamName { get; init; }
    /// <summary>Raw logo image bytes for the header, or null. Paired with <see cref="LogoContentType"/>.</summary>
    public byte[]? LogoBytes { get; init; }
    public string? LogoContentType { get; init; }

    /// <summary>Enabled body sections in print order (from the administered layout). Empty = default all.</summary>
    public IReadOnlyList<ReportSection> Sections { get; init; } = Enum.GetValues<ReportSection>();

    public required string CaseNumber { get; init; }
    public required string Title { get; init; }
    public required string Classification { get; init; }
    public required string Phase { get; init; }
    public required string Severity { get; init; }
    public required string Origin { get; init; }
    public string? VendorName { get; init; }
    public string? DetectionCaseId { get; init; }
    public string? Summary { get; init; }
    public string? DataTypesInvolved { get; init; }
    public string? ImpactedAssets { get; init; }

    // Structured impact assessment (E-12).
    public int? AffectedIndividualsCount { get; init; }
    public string? DataElementsSummary { get; init; }
    /// <summary>Regulatory-notification grouping (X-03): which jurisdictions the involved data elements
    /// trigger notification in, e.g. "NY — Social Security number, Medical / health information; US — Payment
    /// card". Null when no involved element carries a notification jurisdiction.</summary>
    public string? NotificationTriggersSummary { get; init; }
    public string? AffectedStates { get; init; }

    public bool LegalReferred { get; init; }
    public string? LegalNote { get; init; }

    public DateTimeOffset? DetectedAtUtc { get; init; }
    public DateTimeOffset? ContainedAtUtc { get; init; }
    public DateTimeOffset? ResolvedAtUtc { get; init; }
    public DateTimeOffset? ClosedAtUtc { get; init; }

    public IReadOnlyList<ReportClassificationItem> ClassificationHistory { get; init; } = [];
    public IReadOnlyList<ReportClassificationItem> SeverityHistory { get; init; } = [];
    public IReadOnlyList<ReportTimelineItem> EventTimeline { get; init; } = [];
    public IReadOnlyList<ReportAttackStep> AttackChain { get; init; } = [];
    public IReadOnlyList<ReportTimelineItem> InvestigationTimeline { get; init; } = [];
    public IReadOnlyList<ReportEvidenceItem> Evidence { get; init; } = [];
    public IReadOnlyList<ReportNoteItem> Notes { get; init; } = [];
    public IReadOnlyList<ReportActionItemRow> ActionItems { get; init; } = [];
    public IReadOnlyList<ReportAssignmentRow> Assignments { get; init; } = [];
    public IReadOnlyList<ReportEntityRow> Entities { get; init; } = [];
    public IReadOnlyList<ReportRelationshipRow> Relationships { get; init; } = [];
    public IReadOnlyList<ReportTechniqueRow> Techniques { get; init; } = [];

    public required string GeneratedBy { get; init; }
    public required DateTimeOffset GeneratedAtUtc { get; init; }

    /// <summary>SHA-256 of the case content (provenance stamp embedded in the document).</summary>
    public required string ContentHash { get; init; }
}
