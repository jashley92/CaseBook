using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Abstractions;

/// <summary>
/// A follow-up item that has passed its due date, flattened for notification (E-03b). Carries the owner id
/// and the case's incident commander so the notifier can resolve a recipient (owner, else IC) without
/// re-loading entities, plus the display fields for the email body. BUG-427: <see cref="OwnerUserId"/> is who the
/// reminder may go to (null when the owner can't be told); <see cref="WrittenOwner"/> is the task's owner as written,
/// for the "owner" the escalation email names.
/// </summary>
public sealed record OverdueActionItem(
    Guid CaseId,
    string CaseNumber,
    string CaseTitle,
    string? IncidentCommanderUserId,
    Guid ActionItemId,
    string Title,
    DateTimeOffset DueAtUtc,
    string? OwnerUserId,
    string? WrittenOwner = null,
    // CAP-36: the case's team, so the channel post goes to the team's chat webhook when it has one.
    Guid? TeamId = null);

/// <summary>Who an overdue follow-up item has escalated to (PROD-03). Values are the escalation order.</summary>
public enum OverdueEscalationTier
{
    /// <summary>The case's incident commander (skipped when they were the first reminder's recipient).</summary>
    IncidentCommander = 1,
    /// <summary>Everyone holding the Manager role in the user directory.</summary>
    Managers = 2,
}

/// <summary>
/// An overdue follow-up item that has stayed overdue long enough to escalate (PROD-03): the item, the tier it
/// has newly reached, and how long it has been overdue, for the email body.
/// </summary>
public sealed record EscalatedActionItem(OverdueActionItem Item, OverdueEscalationTier Tier, double HoursOverdue);

/// <summary>
/// A follow-up item whose due date is approaching but not yet passed (E-03d), flattened for notification.
/// Same shape as <see cref="OverdueActionItem"/> — carried as a distinct type so the "due soon" and
/// "overdue" notification paths (and their notify-once trackers) stay independent.
/// </summary>
public sealed record DueSoonActionItem(
    Guid CaseId,
    string CaseNumber,
    string CaseTitle,
    string? IncidentCommanderUserId,
    Guid ActionItemId,
    string Title,
    DateTimeOffset DueAtUtc,
    string? OwnerUserId,
    Guid? TeamId = null);   // CAP-36: as OverdueActionItem.TeamId

/// <summary>
/// A case whose regulatory notification deadline (PROD-07) is approaching or already passed, flattened for
/// notification (PROD-37). Carries the resolved recipient user-ids (the incident commander plus the case's
/// assignees) so the notifier can address them without re-loading, plus the headline jurisdiction's standing
/// for the email body. <see cref="State"/> is always <see cref="SlaState.AtRisk"/> or
/// <see cref="SlaState.Breached"/> — the scanner only raises the attention-worthy bands. BUG-619: it names the
/// jurisdictions on that clock it carries, so each is marked as sent on its own.
/// </summary>
public sealed record DeadlineReminder(
    Guid CaseId,
    string CaseNumber,
    string CaseTitle,
    Severity Severity,
    IReadOnlyList<string> RecipientUserIds,
    SlaState State,
    IReadOnlyList<DeadlineJurisdiction> Jurisdictions,
    DateTimeOffset? DueAtUtc,
    TimeSpan? Remaining,
    Guid? TeamId = null)   // CAP-36: as OverdueActionItem.TeamId
{
    public IReadOnlyList<string> JurisdictionCodes => Jurisdictions.Select(j => j.Code).ToList();

    public string JurisdictionLabel => string.Join(", ", Jurisdictions.Select(j => j.Label));
}

/// <summary>BUG-619: a jurisdiction a <see cref="DeadlineReminder"/> is for: its code and how it's shown.</summary>
public sealed record DeadlineJurisdiction(string Code, string Label);

/// <summary>
/// An open case that has gone quiet — no recorded activity for longer than its severity's threshold —
/// flattened for notification (PROD-38). Carries the resolved recipient user-ids (incident commander +
/// assignees) and the quiet-spell facts for the email body.
/// </summary>
public sealed record StaleCaseReminder(
    Guid CaseId,
    string CaseNumber,
    string CaseTitle,
    Severity Severity,
    IReadOnlyList<string> RecipientUserIds,
    DateTimeOffset LastActivityAtUtc,
    int DaysInactive,
    int ThresholdDays,
    Guid? TeamId = null);   // CAP-36: as OverdueActionItem.TeamId

/// <summary>One open, dated follow-up item on a user's work digest (PROD-39), flattened for the email body.</summary>
public sealed record DigestItem(string CaseNumber, string TaskTitle, Severity Severity, DateTimeOffset DueAtUtc);

/// <summary>
/// A single user's consolidated work digest (PROD-39): their open, dated follow-up items grouped into the
/// familiar agenda bands. Sent on the cadence they chose, in place of a scatter of per-item reminders.
/// </summary>
/// <param name="ImportsWaiting">CAP-01: for a reviewer, the imports they could see that have waited for review longer than
/// <paramref name="ImportWaitingHours"/>; null or none leaves the line out.</param>
public sealed record UserDigest(
    string UserId,
    DigestCadence Cadence,
    IReadOnlyList<DigestItem> Overdue,
    IReadOnlyList<DigestItem> DueToday,
    IReadOnlyList<DigestItem> DueThisWeek,
    Import.PendingImportCount? ImportsWaiting = null,
    int ImportWaitingHours = 0)
{
    public int TotalItems => Overdue.Count + DueToday.Count + DueThisWeek.Count;

    /// <summary>CAP-01: whether there's anything to send: an item, or imports waiting too long.</summary>
    public bool HasContent => TotalItems > 0 || ImportsWaiting is { Count: > 0 };
}

/// <summary>
/// Case-lifecycle notifications (who to tell, and how) — kept out of the use-case layer so recipient
/// configuration and the delivery channel live in Infrastructure. Implementations must not throw.
/// </summary>
public interface ICaseNotifications
{
    /// <summary>Called after a reclassification is persisted (e.g. to alert Legal on a Breach escalation).</summary>
    Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default);

    /// <summary>
    /// INV-37: called after a note @mentioning teammates is saved (only the people newly mentioned in that version).
    /// Emails each of them (resolved via the user directory) with a link to the note, skipping the author.
    /// Best-effort and gated like the other triggers. A default no-op is provided so test doubles need not change.
    /// </summary>
    Task OnMentionedAsync(Case c, string byUserId, IReadOnlyCollection<string> mentionedUserIds,
        string noteExcerpt, Guid noteId, CancellationToken ct = default) => Task.CompletedTask;

    /// <summary>
    /// INV-37: called after a handoff is recorded, when the person handing off chose to notify the recipient.
    /// Emails them that the case is theirs to pick up, with the handoff text. Default no-op for test doubles.
    /// </summary>
    Task OnHandedOffAsync(Case c, string byUserId, string toUserId, string handoff, CancellationToken ct = default)
        => Task.CompletedTask;

    /// <summary>
    /// Called after someone is assigned to a case (E-03b). Emails the assignee (resolved via the user
    /// directory) that they have a new case role. Skips self-assignments and is gated by config.
    /// </summary>
    Task OnAssignedAsync(Case c, string assigneeUserId, string assigneeDisplayName, CaseAssignmentRole role,
        string assignedByUserId, CancellationToken ct = default);

    /// <summary>
    /// Called by the scheduled overdue scan (E-03b) with the items that have <em>newly</em> become overdue.
    /// Resolves a recipient per item (its owner, else the case's incident commander), groups by recipient,
    /// and sends one reminder each. Gated by config; a no-op when no recipients resolve.
    /// </summary>
    Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default);

    /// <summary>
    /// Called by the scheduled due-soon scan (E-03d) with items whose due date falls within the lead window
    /// and that have <em>not</em> yet been reminded for this due date. Resolves a recipient per item (its
    /// owner, else the case's incident commander), groups by recipient, and sends one reminder each. Gated
    /// by config; a no-op when no recipients resolve.
    /// </summary>
    Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default);

    /// <summary>
    /// Called by the overdue scan (PROD-03) with items that have <em>newly</em> reached an escalation tier:
    /// still overdue after the configured hours, so the reminder widens from the owner to the incident
    /// commander, then to managers. Notifies only — nothing here changes the item or the case. A default no-op
    /// is provided so existing implementers (and test doubles) need not change.
    /// </summary>
    Task OnActionItemsEscalatedAsync(IReadOnlyList<EscalatedActionItem> items, CancellationToken ct = default)
        => Task.CompletedTask;

    /// <summary>
    /// Called by the scheduled regulatory-deadline scan (PROD-37) with the cases that have <em>newly</em>
    /// crossed into an at-risk or breached notification-deadline band and have not yet been reminded for it.
    /// Resolves each case's recipients (incident commander + assignees), groups by recipient, and sends one
    /// reminder each. A default no-op is provided so existing implementers (and test doubles) need not change;
    /// the real <c>CaseNotifications</c> overrides it. Gated by config; a no-op when no recipients resolve.
    /// Reminds only — a human still records the reported milestone; nothing here mutates case state.
    /// </summary>
    Task OnDeadlineApproachingAsync(IReadOnlyList<DeadlineReminder> reminders, CancellationToken ct = default)
        => Task.CompletedTask;

    /// <summary>
    /// Called by the scheduled stale-case scan (PROD-38) with the open cases that have <em>newly</em> gone
    /// quiet past their severity's threshold and have not yet been nudged for this quiet spell. Resolves each
    /// case's recipients (incident commander + assignees), groups by recipient, and sends one nudge each. A
    /// default no-op is provided so existing implementers (and test doubles) need not change; the real
    /// <c>CaseNotifications</c> overrides it. Gated by config; a no-op when no recipients resolve. Nudges
    /// only — nothing here mutates case state.
    /// </summary>
    Task OnCasesStaleAsync(IReadOnlyList<StaleCaseReminder> reminders, CancellationToken ct = default)
        => Task.CompletedTask;

    /// <summary>
    /// Called by the scheduled digest scan (PROD-39) with one user's consolidated work digest, on the cadence
    /// they opted into. Resolves the user's address and sends a single grouped summary — the one email that
    /// stands in for a scatter of per-item reminders. A default no-op is provided so existing implementers
    /// (and test doubles) need not change; the real <c>CaseNotifications</c> overrides it. A no-op when the
    /// user has no address on file. Reminds only — nothing here mutates case state.
    /// </summary>
    Task OnDigestAsync(UserDigest digest, CancellationToken ct = default) => Task.CompletedTask;

    /// <summary>
    /// PROD-15: the scheduled executive report — last quarter's program headline figures (E-31) for the managers,
    /// with a link to the full report. Default no-op so existing implementers and test doubles need not change.
    /// </summary>
    Task OnExecutiveReportAsync(IncidentManager.Application.Dashboards.ProgramReport report, CancellationToken ct = default)
        => Task.CompletedTask;

    /// <summary>
    /// CAP-01: a case-import document arrived through the API and waits in the review queue. Emails the reviewers named
    /// (<see cref="ImportSubmission.ReviewerUserIds"/>, already cut to those who may see its target) and posts to the team
    /// channel, each only when its toggle is on (both off by default). Tells only: nothing is applied (ADR 0004). A default
    /// no-op so existing implementers and test doubles need not change.
    /// </summary>
    Task OnImportSubmittedAsync(ImportSubmission submission, CancellationToken ct = default) => Task.CompletedTask;

    /// <summary>
    /// CAP-10: the monthly retention-review notice to the Legal / Privacy distribution: how many closed cases are past
    /// retention and waiting for an administrator's review. Counts only, no case named (the distribution is addresses,
    /// not people CaseBook can check need-to-know for). Tells only: nothing is archived or deleted (ADR 0004). A default
    /// no-op so existing implementers and test doubles need not change.
    /// </summary>
    Task OnRetentionReviewDueAsync(Notifications.RetentionReviewCount count, CancellationToken ct = default) => Task.CompletedTask;
}

/// <summary>
/// CAP-01: a queued import as its notification describes it. <see cref="Summary"/> is the queue's line ("Into …" or
/// "New case: …", with the item count), which the shared channel leaves out when <see cref="IsRestricted"/> (its target
/// case is restricted). <see cref="ReviewerUserIds"/> are the people who may be emailed.
/// </summary>
public sealed record ImportSubmission(
    Guid PendingImportId,
    string SubmittedBy,
    string? Origin,
    string Summary,
    int ItemCount,
    Guid? TargetCaseId,
    bool IsRestricted,
    bool IsExercise,
    IReadOnlyList<string> ReviewerUserIds,
    // CAP-36: the team of the case it targets (an existing case's, or the team a new case names), so the channel post goes
    // to that team's chat webhook when it has one.
    Guid? TeamId = null);
