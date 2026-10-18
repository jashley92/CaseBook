using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IncidentManager.Application.Compliance;

/// <summary>CAP-10: how long closed cases are kept before they're listed for review, bound from <c>Retention</c>.</summary>
public sealed class CaseRetentionOptions
{
    /// <summary>Years after closing before a case is listed in the retention review. 0 turns the review off.</summary>
    public int CaseYears { get; set; } = 7;
}

/// <summary>One regulatory deadline still running on a case in the retention review (its notice isn't recorded).</summary>
public sealed record RetentionDeadline(string Jurisdiction, DateTimeOffset? DueAtUtc, SlaState State);

/// <summary>
/// CAP-10: a closed, not-archived case past retention, with what stands in the way of archiving it: a legal hold (or a
/// pending release of one), and regulatory deadlines whose notice isn't recorded. Open improvement actions are shown for
/// the reviewer's judgment; they don't block archiving (they outlive their case by design, PROD-41).
/// </summary>
public sealed record RetentionReviewRow(
    Guid CaseId, string CaseNumber, string Title, bool IsRestricted, DateTimeOffset ClosedAtUtc,
    bool LegalHold, bool HoldReleasePending, int OpenImprovementActions, IReadOnlyList<RetentionDeadline> UnreportedDeadlines)
{
    /// <summary>What <see cref="CaseService.SetArchivedAsync"/> would refuse it for, or null when it can be archived.</summary>
    public string? Blocker => LegalHold ? "Under legal hold"
        : UnreportedDeadlines.Count > 0 ? "Regulatory notice not recorded" : null;

    public bool CanArchive => Blocker is null;
}

/// <summary>The retention review: the setting it was built with, the cut-off, and the cases due. Off when years is 0.</summary>
public sealed record RetentionReview(int Years, DateTimeOffset? CutoffUtc, IReadOnlyList<RetentionReviewRow> Rows)
{
    public bool Off => Years <= 0;
}

/// <summary>What happened to one case of an archive batch.</summary>
public enum RetentionArchiveOutcome
{
    Archived,
    /// <summary>The archive was refused (a legal hold, a deadline running): the detail says why.</summary>
    Refused,
    /// <summary>It's no longer in the review: reopened, archived meanwhile, out of sight, or the setting changed.</summary>
    NoLongerDue
}

public sealed record RetentionArchiveResult(Guid CaseId, RetentionArchiveOutcome Outcome, string? Detail = null);

/// <summary>
/// CAP-10: the retention review. Lists closed, not-archived cases whose closing is older than <c>Retention:CaseYears</c>,
/// with each one's legal hold, open improvement actions and unreported deadlines, and archives the ones a person picks,
/// at most <see cref="MaxBatch"/> at a time, through <see cref="CaseService.SetArchivedAsync"/> (which refuses a hold or
/// a running deadline, BUG-10). Nothing is purged, and nothing is archived without a person choosing it (ADR 0004): the
/// nightly count (<see cref="Notifications.RetentionReviewScanner"/>) only counts. Administer only; the cases are the
/// administrator's own need-to-know view (ForUser), as everywhere else. Exercises aren't listed (L7).
/// </summary>
public sealed class RetentionReviewService(
    IAppDbContextFactory factory,
    ICurrentUser user,
    IClock clock,
    CaseService cases,
    IOptionsMonitor<CaseRetentionOptions>? options = null,
    NotificationDeadlineService? deadlines = null,
    ISecurityEventSink? siem = null)
{
    /// <summary>The most cases one archive batch takes (E-18's metering cap).</summary>
    public const int MaxBatch = 25;

    /// <summary>The longest retention the settings page allows; a larger value in the server's file counts as this.</summary>
    public const int MaxYears = 100;

    /// <summary>The setting now, kept within 0 to <see cref="MaxYears"/> (BUG-262: the server's file isn't checked).</summary>
    public int Years => Math.Clamp(options?.CurrentValue.CaseYears ?? 7, 0, MaxYears);

    /// <summary>Closings before this instant are past retention.</summary>
    public static DateTimeOffset Cutoff(DateTimeOffset now, int years) => now.AddYears(-Math.Clamp(years, 1, MaxYears));

    /// <summary>The cases due for review in <paramref name="source"/>: closed, not archived, closed before the cut-off.</summary>
    public static IQueryable<Case> Due(IQueryable<Case> source, DateTimeOffset cutoffUtc) =>
        source.ExcludingExercises()
            .Where(c => c.Phase == CasePhase.Closed && !c.IsArchived && c.ClosedAtUtc != null && c.ClosedAtUtc < cutoffUtc);

    public async Task<RetentionReview> BuildAsync(CancellationToken ct = default)
    {
        AdminActionPermissions.Require<RetentionReviewService>(user, siem);
        var years = Years;
        if (years == 0) return new RetentionReview(0, null, []);
        var cutoff = Cutoff(clock.UtcNow, years);

        using var db = factory.CreateDbContext();
        var scope = Due(db.Cases.AsNoTracking().ForUser(user), cutoff);
        var found = await scope
            .Select(c => new
            {
                c.Id, c.CaseNumber, c.Title, c.IsRestricted, c.ClosedAtUtc, c.LegalHold,
                Pending = c.LegalHoldReleaseRequestedBy != null,
                OpenActions = db.ImprovementActions.Count(a => a.CaseId == c.Id
                    && a.Status != ImprovementActionStatus.Completed && a.Status != ImprovementActionStatus.NotPursued),
            })
            .ToListAsync(ct);
        // Every jurisdiction's clock for the unreported ones, with the live rules: what SetArchivedAsync refuses on.
        Dictionary<Guid, IReadOnlyList<NotificationDeadlineStatus>> clocks = deadlines is null ? [] : await deadlines.AllNowAsync(db, scope, ct);

        var rows = found
            .OrderBy(c => c.ClosedAtUtc).ThenBy(c => c.CaseNumber, StringComparer.Ordinal)
            .Select(c => new RetentionReviewRow(c.Id, c.CaseNumber, c.Title, c.IsRestricted, c.ClosedAtUtc!.Value, c.LegalHold,
                c.Pending, c.OpenActions,
                clocks.TryGetValue(c.Id, out var s)
                    ? s.Select(x => new RetentionDeadline(x.JurisdictionLabel, x.DueAtUtc, x.State)).ToList()
                    : []))
            .ToList();
        return new RetentionReview(years, cutoff, rows);
    }

    /// <summary>
    /// Archives the cases picked from the review, one save each, and says what happened to each. A case no longer in the
    /// review (reopened, archived meanwhile, not visible, the setting changed) is left alone; a refusal (legal hold, a
    /// deadline running) is reported, and the rest go ahead. At most <see cref="MaxBatch"/> cases.
    /// </summary>
    public async Task<IReadOnlyList<RetentionArchiveResult>> ArchiveAsync(IReadOnlyCollection<Guid> caseIds, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<RetentionReviewService>(user, siem);
        var ids = (caseIds ?? []).Distinct().ToList();
        if (ids.Count == 0) throw new ArgumentException("Pick the cases to archive.");
        if (ids.Count > MaxBatch) throw new ArgumentException($"Archive at most {MaxBatch} cases at a time.");
        var years = Years;
        if (years == 0) throw new InvalidOperationException("The retention review is off: the case retention setting is 0.");

        HashSet<Guid> due;
        using (var db = factory.CreateDbContext())
            due = (await Due(db.Cases.AsNoTracking().ForUser(user), Cutoff(clock.UtcNow, years))
                .Where(c => ids.Contains(c.Id)).Select(c => c.Id).ToListAsync(ct)).ToHashSet();

        var results = new List<RetentionArchiveResult>(ids.Count);
        foreach (var id in ids)
        {
            if (!due.Contains(id))
            {
                results.Add(new RetentionArchiveResult(id, RetentionArchiveOutcome.NoLongerDue,
                    "It's no longer closed and past retention, or it was archived meanwhile."));
                continue;
            }
            try
            {
                await cases.SetArchivedAsync(id, true, ct);
                results.Add(new RetentionArchiveResult(id, RetentionArchiveOutcome.Archived));
            }
            catch (InvalidOperationException ex)
            {
                results.Add(new RetentionArchiveResult(id, RetentionArchiveOutcome.Refused, ex.Message));
            }
            catch (Exception ex) when (ex is StaleEditException or DbUpdateConcurrencyException)
            {
                // One case changed under the batch: it's reported, and the rest still go ahead.
                results.Add(new RetentionArchiveResult(id, RetentionArchiveOutcome.Refused,
                    "Someone changed it while it was being archived. Reload the list and try again."));
            }
        }
        return results;
    }
}
