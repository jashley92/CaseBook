using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Import;

/// <summary>The outcome of parsing an import document: the document, or a friendly error explaining why not.</summary>
public sealed record CaseImportParse(CaseImportDocument? Document, string? Error)
{
    public bool Ok => Document is not null && Error is null;
    public static CaseImportParse Fail(string error) => new(null, error);
    public static CaseImportParse Success(CaseImportDocument doc) => new(doc, null);
}

/// <summary>Which kind of case the import will land in.</summary>
public enum CaseImportTargetKind { NewCase, ExistingCase }

/// <summary>
/// The reviewable, editable preview of an import before anything is written. Rows carry validation warnings
/// and an <c>Include</c> toggle; enum fields have been resolved (unknown values fell back to a default and
/// were flagged in <see cref="Warnings"/>). The <c>Applied</c> flags + <see cref="CreatedCaseId"/> make
/// <see cref="CaseImportService.ApplyAsync"/> resume-safe if a mid-apply write fails (mirrors CreateCase).
/// </summary>
public sealed class CaseImportPreview
{
    public CaseImportTargetKind TargetKind { get; set; } = CaseImportTargetKind.NewCase;

    /// <summary>New-case opening fields (editable), when <see cref="TargetKind"/> is <see cref="CaseImportTargetKind.NewCase"/>.</summary>
    public CreateCaseRequest? NewCase { get; set; }

    /// <summary>The resolved existing target, when <see cref="TargetKind"/> is <see cref="CaseImportTargetKind.ExistingCase"/>.</summary>
    public Guid? ExistingCaseId { get; set; }
    public string? ExistingCaseNumber { get; set; }
    public string? ExistingTitle { get; set; }

    /// <summary>Provenance default applied to imported entities/timeline as their <c>Source</c> (editable).</summary>
    public string? Origin { get; set; }

    public bool IncludeSummary { get; set; }
    public string? Summary { get; set; }

    public List<ImportTimelineRow> Timeline { get; } = new();
    public List<ImportEntityRow> Entities { get; } = new();
    public List<ImportActionItemRow> ActionItems { get; } = new();

    /// <summary>Document-level notes about what was clamped, defaulted, dropped, or fell back to a default.</summary>
    public List<string> Warnings { get; } = new();

    // Resume-safe apply state (not user-facing).
    public Guid? CreatedCaseId { get; set; }
    public bool SummaryApplied { get; set; }

    public int IncludedItemCount =>
        (IncludeSummary && !string.IsNullOrWhiteSpace(Summary) ? 1 : 0)
        + Timeline.Count(r => r.Include) + Entities.Count(r => r.Include) + ActionItems.Count(r => r.Include);

    public bool HasAnything => IncludedItemCount > 0;
}

/// <summary>One editable timeline row in the preview.</summary>
public sealed class ImportTimelineRow
{
    public bool Include { get; set; } = true;
    public bool Applied { get; set; }
    public DateTimeOffset OccurredAtUtc { get; set; }
    public TimelineKind Kind { get; set; } = TimelineKind.Investigation;
    public TimelineEntryType Type { get; set; } = TimelineEntryType.Communication;
    public string Description { get; set; } = string.Empty;
    public string? Source { get; set; }
    public string? Warning { get; set; }
}

/// <summary>One editable entity/IOC row in the preview.</summary>
public sealed class ImportEntityRow
{
    public bool Include { get; set; } = true;
    public bool Applied { get; set; }
    public EntityType Type { get; set; } = EntityType.Other;
    public string Value { get; set; } = string.Empty;
    public string? Label { get; set; }
    public EntityDisposition Disposition { get; set; } = EntityDisposition.Unknown;
    public string? Description { get; set; }
    public string? Source { get; set; }
    public string? Warning { get; set; }
}

/// <summary>One editable action-item row in the preview.</summary>
public sealed class ImportActionItemRow
{
    public bool Include { get; set; } = true;
    public bool Applied { get; set; }
    public string Title { get; set; } = string.Empty;
    public string? Owner { get; set; }
    public DateTimeOffset? DueAtUtc { get; set; }
    public string? Warning { get; set; }
}

/// <summary>A queued programmatic import awaiting human review (PROD-33), for the pending-imports list.</summary>
public sealed record PendingImportSummary(
    Guid Id, string SubmittedBy, DateTimeOffset SubmittedAtUtc, string? Origin, string Summary);

/// <summary>Counts written by an apply, plus the resulting case for navigation.</summary>
public sealed record CaseImportResult(
    Guid CaseId, string CaseNumber, bool CaseCreated,
    int Notes, int Timeline, int Entities, int ActionItems)
{
    public int Total => Notes + Timeline + Entities + ActionItems;
}
