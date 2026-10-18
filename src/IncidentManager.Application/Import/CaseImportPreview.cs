using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Import;

/// <summary>The outcome of parsing an import document: the document, or a friendly error explaining why not.</summary>
public sealed record CaseImportParse(CaseImportDocument? Document, string? Error)
{
    /// <summary>BUG-636: how many of the document's times had no offset, and the zone they were read in.</summary>
    public int UnzonedTimes { get; init; }
    public TimeZoneInfo? UnzonedZone { get; init; }

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

    /// <summary>CAP-14: the detection case id the document targets, while no review has resolved it (a submission's own
    /// preview, built as the producer sent it: which case it names is the reviewer's view to decide).</summary>
    public string? DetectionCaseId { get; set; }

    /// <summary>Provenance default applied to imported entities/timeline as their <c>Source</c> (editable).</summary>
    public string? Origin { get; set; }

    public bool IncludeSummary { get; set; }
    public string? Summary { get; set; }

    public List<ImportTimelineRow> Timeline { get; } = new();
    public List<ImportEntityRow> Entities { get; } = new();
    public List<ImportActionItemRow> ActionItems { get; } = new();

    /// <summary>Document-level notes about what was clamped, defaulted, dropped, or fell back to a default.</summary>
    public List<string> Warnings { get; } = new();

    // CAP-35 (schema v2): a new case's history and team. Applied only to a new case, after everything else, so the case
    // closes (when its history says so) last, with its content in.

    /// <summary>CAP-35: the phase transitions to apply, oldest first.</summary>
    public List<ImportHistoryRow> History { get; } = new();

    /// <summary>CAP-35: the outcome key and conclusion of a history that ends in Closed.</summary>
    public string? Outcome { get; set; }
    public string? Conclusion { get; set; }

    /// <summary>CAP-35: the incident commander as the document names them, and who that resolved to in the user directory
    /// (null when no user matched: warned, and not applied).</summary>
    public ImportAssignmentRow? IncidentCommander { get; set; }
    public List<ImportAssignmentRow> Assignments { get; } = new();

    /// <summary>CAP-36: the owning team as the document names it (its key or name), and the team's name once it's matched to
    /// an active team (the id is <see cref="CreateCaseRequest.TeamId"/> on <see cref="NewCase"/>, which the reviewer can change).</summary>
    public string? TeamNamed { get; set; }

    /// <summary>CAP-35: why the history can't be applied as it stands (out of order, before detection, in the future, a
    /// close without its outcome), or null. Apply refuses while it's set, before writing anything.</summary>
    public string? HistoryProblem { get; set; }

    /// <summary>CAP-35: whether the document carries a history or team (v2), so a reviewer sees it's a historical record.</summary>
    public bool HasHistory => History.Count > 0 || IncidentCommander is not null || Assignments.Count > 0;

    /// <summary>CAP-35: the override reason a close takes when its gate's checks can't be met.</summary>
    public string ImportedRecordReason => $"imported record: {(string.IsNullOrWhiteSpace(Origin) ? "import" : Origin.Trim())}";

    /// <summary>CAP-35 review: whether the history ends in Closed (a batch confirm leaves such a one for a person: its close
    /// may override the close gate).</summary>
    public bool ClosesCase => History.Count > 0 && History[^1].Phase == CasePhase.Closed;

    /// <summary>CAP-35 review: the reason the close records, trimmed: the closing step's own, or the conclusion standing in
    /// for it (as <see cref="CaseService.ChangePhaseAsync"/> does, clipped to the reason's 2,000).</summary>
    public string CloseReason
    {
        get
        {
            var own = ClosesCase ? History[^1].Reason?.Trim() : null;
            var reason = string.IsNullOrEmpty(own) ? (Conclusion ?? "").Trim() : own;
            return Common.TextFit.Cap(reason, MaxCloseReason, "");
        }
    }

    private const int MaxCloseReason = 2000;

    /// <summary>
    /// CAP-35 review: the override justification a close takes when its gate's checks can't be met:
    /// <see cref="ImportedRecordReason"/>, followed by the close's reason when that alone is shorter than the gate's
    /// commentary minimum (<paramref name="minLength"/>), so an override is never refused for a short justification.
    /// </summary>
    public string CloseOverrideReason(int minLength) => ImportedRecordReason.Length >= minLength
        ? ImportedRecordReason
        : Common.TextFit.Cap($"{ImportedRecordReason}. {CloseReason}", MaxCloseReason, "");

    // Resume-safe apply state (not user-facing).
    public Guid? CreatedCaseId { get; set; }
    public bool SummaryApplied { get; set; }

    /// <summary>CAP-35 review: set each time a failed apply is saved on its queued row to resume from, so a claim made with
    /// a preview from before that (another reviewer's stale page) is refused rather than creating the case again.</summary>
    public Guid? ResumeStamp { get; set; }

    public int IncludedItemCount =>
        (IncludeSummary && !string.IsNullOrWhiteSpace(Summary) ? 1 : 0)
        + Timeline.Count(r => r.Include) + Entities.Count(r => r.Include) + ActionItems.Count(r => r.Include)
        // CAP-35: a new case's history and the team members found in the directory.
        + (TargetKind == CaseImportTargetKind.NewCase
            ? History.Count + (IncidentCommander?.UserId is null ? 0 : 1) + Assignments.Count(a => a.UserId is not null) : 0);

    public bool HasAnything => IncludedItemCount > 0;
}

/// <summary>One editable timeline row in the preview.</summary>
public sealed class ImportTimelineRow
{
    public bool Include { get; set; } = true;
    public bool Applied { get; set; }
    public DateTimeOffset OccurredAtUtc { get; set; }
    /// <summary>ST-03: an event step's time as stated; anything but exact applies only to an Event row.</summary>
    public TimePrecision Precision { get; set; } = TimePrecision.Exact;
    /// <summary>BUG-15: the entry this row became, so a retry can place a following not-stated step after it.</summary>
    public Guid? AppliedId { get; set; }
    public DateTimeOffset? OccurredUntilUtc { get; set; }
    public TimelineKind Kind { get; set; } = TimelineKind.Investigation;
    public TimelineEntryType Type { get; set; } = TimelineEntryType.Communication;
    public string Description { get; set; } = string.Empty;
    public string? Source { get; set; }
    public string? Warning { get; set; }

    // INV-18: a Decision row's details; the why is required to apply it as a decision.
    public string? Rationale { get; set; }
    public string? OptionsConsidered { get; set; }
    public string? DecidedBy { get; set; }
}

/// <summary>CAP-35: one phase transition of an imported case's history.</summary>
public sealed class ImportHistoryRow
{
    public bool Applied { get; set; }
    public CasePhase Phase { get; set; }
    public DateTimeOffset AtUtc { get; set; }
    public string? Reason { get; set; }
    public DateTimeOffset? ContainedAtUtc { get; set; }
    public string? ContainmentNotNeeded { get; set; }
    public DateTimeOffset? ResolvedAtUtc { get; set; }
}

/// <summary>CAP-35: one member of an imported case's team: as the document named them (<see cref="Named"/>) and who that is
/// in the user directory (<see cref="UserId"/>, null when nobody matched).</summary>
public sealed class ImportAssignmentRow
{
    public bool Applied { get; set; }
    public string Named { get; set; } = string.Empty;
    public string? UserId { get; set; }
    public string? DisplayName { get; set; }
    public CaseAssignmentRole Role { get; set; } = CaseAssignmentRole.Analyst;
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
    /// <summary>BUG-152: the marking the document gave it (null: the case's default applies).</summary>
    public TlpLevel? Tlp { get; set; }
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

/// <summary>
/// CAP-35 review: a claim refused because the preview predates the queued import's resume state: an apply since it was
/// opened stopped part-way and was put back, so applying this preview would write again what that one wrote.
/// </summary>
public sealed class StaleResumeException : InvalidOperationException
{
    public StaleResumeException() : base("An apply of this import stopped part-way since you opened it, and was put back in the " +
        "queue with what it wrote. Reopen it from the queue to carry on into the same case.") { }
}

/// <summary>A queued programmatic import awaiting human review (PROD-33), for the pending-imports list.</summary>
/// <param name="StuckClaimedBy">WF-18: set when an apply of it stopped without finishing (claimed by this reviewer, over
/// <see cref="CaseImportService.StaleClaim"/> ago, with no case recorded); any reviewer can reopen it.</param>
public sealed record PendingImportSummary(
    Guid Id, string SubmittedBy, DateTimeOffset SubmittedAtUtc, string? Origin, string Summary,
    string? StuckClaimedBy = null, DateTimeOffset? StuckSinceUtc = null);

/// <summary>CAP-13: what became of a submission, as its sender reads it over the API.</summary>
/// <param name="Status"><c>pending</c> (waiting, or being applied right now), <c>applied</c> or <c>rejected</c>.</param>
/// <param name="ResolvedCaseNumber">The case it went into, as numbered now; null unless applied into a case the caller can
/// see (with <paramref name="ResolvedCaseId"/>).</param>
public sealed record ImportSubmissionStatus(string Status, DateTimeOffset? DecidedAtUtc, string? ResolvedCaseNumber, Guid? ResolvedCaseId);

/// <summary>CAP-35: what became of one submission in a batch confirm: applied into <paramref name="CaseNumber"/>, or left in
/// the queue with why (<paramref name="Message"/>), for a person to review on its own.</summary>
public sealed record BatchConfirmItem(Guid PendingImportId, string Summary, bool Applied, string? CaseNumber, Guid? CaseId, string? Message);

/// <summary>Counts written by an apply, plus the resulting case for navigation.</summary>
public sealed record CaseImportResult(
    Guid CaseId, string CaseNumber, bool CaseCreated,
    int Notes, int Timeline, int Entities, int ActionItems)
{
    public int Total => Notes + Timeline + Entities + ActionItems;
}
