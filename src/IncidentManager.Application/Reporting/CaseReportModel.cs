using IncidentManager.Application.Content;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Reporting;

public sealed record ReportClassificationItem(DateTimeOffset AtUtc, string From, string To, string Reason, string By);
public sealed record ReportTimelineItem(DateTimeOffset OccurredAtUtc, string Type, string Description, string? Source);
public sealed record ReportEvidenceItem(string FileName, long SizeBytes, string Sha256, DateTimeOffset UploadedAtUtc, string UploadedBy);
/// <summary>An analyst note: <see cref="Body"/> is plain text; <see cref="Blocks"/> keeps its Markdown formatting for print.</summary>
public sealed record ReportNoteItem(DateTimeOffset AtUtc, string Author, string Body, IReadOnlyList<RichBlock>? Blocks = null);
public sealed record ReportActionItemRow(string Title, string? Owner, DateTimeOffset? DueAtUtc, string Status);
public sealed record ReportAssignmentRow(string User, string Role);
/// <summary>E-26: the post-incident review, as printed in the lessons-learned report (Markdown kept as blocks).</summary>
public sealed record ReportReview(IReadOnlyList<RichBlock> WhatHappened, IReadOnlyList<RichBlock> ContributingFactors,
    IReadOnlyList<RichBlock> WhatWorkedWell, IReadOnlyList<RichBlock> OpportunitiesToImprove, bool NoActionsIdentified);
/// <summary>PROD-41: one improvement action row in the lessons-learned report.</summary>
public sealed record ReportImprovementActionRow(string Title, string? RelatedArea, string? Details, string Owner,
    DateTimeOffset? TargetDateUtc, string Status, string? OutcomeNote);
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

    /// <summary>
    /// Which document this model renders. <see cref="ReportKind.Case"/> is the examiner-facing case report
    /// (sections below); <see cref="ReportKind.LessonsLearned"/> renders only the review + improvement actions
    /// (E-26/PROD-41), kept as a separate document so it can be handled and shared on its own terms.
    /// </summary>
    public ReportKind Kind { get; init; } = ReportKind.Case;

    public bool IsLessonsLearned => Kind == ReportKind.LessonsLearned;

    /// <summary>
    /// Optional confidentiality legend printed at the top of every page (lessons-learned report only). Admin-set
    /// wording (e.g. a privilege marking counsel has approved); null prints nothing.
    /// </summary>
    public string? Legend { get; init; }

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
    /// <summary>The Summary with its Markdown formatting kept (headings, emphasis, lists) for print.</summary>
    public IReadOnlyList<RichBlock> SummaryBlocks { get; init; } = [];
    /// <summary>E-36: free-text data context. Printed as analyst notes, beneath the authoritative data elements.</summary>
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

    // Materiality determination (PROD-18): a Legal/committee decision recorded for the file. Surfaced in the
    // report because Legal reads the report, not the app. Only rendered once a determination has been started.
    /// <summary>Human label for the current determination (e.g. "Material", "Under review"); null when Undetermined.</summary>
    public string? MaterialityStatus { get; init; }
    /// <summary>True once a final material / not-material call has been recorded.</summary>
    public bool MaterialityDetermined { get; init; }
    public string? MaterialityDecisionMaker { get; init; }
    public DateTimeOffset? MaterialityDecidedOnUtc { get; init; }
    public string? MaterialityRationale { get; init; }
    /// <summary>UX-10: a legal hold is in effect — case data must be preserved (no deletion). Surfaced in
    /// the report because Legal reads the report, not the app.</summary>
    public bool LegalHold { get; init; }

    public DateTimeOffset? DetectedAtUtc { get; init; }
    /// <summary>PROD-07: the regulatory-notification milestone, when set. Legal reads the report, not the app.</summary>
    public DateTimeOffset? ReportedAtUtc { get; init; }
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

    // Lessons-learned report only (Kind == LessonsLearned).
    public ReportReview? Review { get; init; }
    public IReadOnlyList<ReportImprovementActionRow> ImprovementActions { get; init; } = [];

    /// <summary>The review's labelled sections in print order, skipping empty ones — shared by every renderer.</summary>
    public IReadOnlyList<(string Label, IReadOnlyList<RichBlock> Blocks)> ReviewParagraphs => Review is null ? [] :
        new (string Label, IReadOnlyList<RichBlock> Blocks)[]
        {
            ("What happened", Review.WhatHappened), ("Contributing factors", Review.ContributingFactors),
            ("What worked well", Review.WhatWorkedWell), ("Opportunities to improve", Review.OpportunitiesToImprove)
        }.Where(p => p.Blocks.Count > 0).ToList();

    /// <summary>What prints when there are no improvement actions: an explicit "none identified", else "(none recorded)".</summary>
    public string NoActionsText => Review?.NoActionsIdentified == true
        ? "The review identified no improvement actions." : "(none recorded)";

    /// <summary>An action's detail cell: the plan, plus the outcome note once it is closed.</summary>
    public static string ActionDetail(ReportImprovementActionRow a) =>
        string.Join(" ", new[] { a.Details, a.OutcomeNote is null ? null : $"Outcome: {a.OutcomeNote}" }
            .Where(s => !string.IsNullOrWhiteSpace(s)));

    /// <summary>The provenance stamp's hash label — the lessons report hashes its own content, not the case row.</summary>
    public string ContentHashLabel => IsLessonsLearned ? "Review content hash" : "Case content hash";
    public IReadOnlyList<ReportAssignmentRow> Assignments { get; init; } = [];
    public IReadOnlyList<ReportEntityRow> Entities { get; init; } = [];
    public IReadOnlyList<ReportRelationshipRow> Relationships { get; init; } = [];
    public IReadOnlyList<ReportTechniqueRow> Techniques { get; init; } = [];

    public required string GeneratedBy { get; init; }
    public required DateTimeOffset GeneratedAtUtc { get; init; }

    /// <summary>SHA-256 of the case content (provenance stamp embedded in the document).</summary>
    public required string ContentHash { get; init; }
}
