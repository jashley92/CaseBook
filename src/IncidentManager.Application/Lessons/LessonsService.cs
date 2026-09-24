using System.Globalization;
using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Common;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Lessons;

/// <summary>A case's post-incident review, resolved for display. <see cref="Stamp"/> guards concurrent edits.</summary>
public sealed record PostIncidentReviewView(
    string? WhatHappened, string? ContributingFactors, string? WhatWorkedWell, string? OpportunitiesToImprove,
    bool NoActionsIdentified, bool IsRecorded, string LastEditedBy, DateTimeOffset LastEditedAtUtc, string Stamp);

/// <summary>One improvement action, resolved for display.</summary>
public sealed record ImprovementActionView(
    Guid Id, Guid CaseId, string Title, string? RelatedArea, string? Details,
    string? OwnerId, string OwnerName, DateTimeOffset? TargetDateUtc, ImprovementActionStatus Status,
    DateTimeOffset? ClosedAtUtc, string? OutcomeNote, bool IsPastTarget, DateTimeOffset CreatedAtUtc);

/// <summary>Everything the case's Review tab shows. <see cref="Review"/> is null until first saved.</summary>
public sealed record CaseLessonsView(PostIncidentReviewView? Review, IReadOnlyList<ImprovementActionView> Actions);

/// <summary>The editable fields of a post-incident review.</summary>
public sealed record PostIncidentReviewInput(
    string? WhatHappened, string? ContributingFactors, string? WhatWorkedWell, string? OpportunitiesToImprove,
    bool NoActionsIdentified);

/// <summary>The editable fields of an improvement action. A closed <see cref="Status"/> requires an <see cref="OutcomeNote"/>.</summary>
public sealed record ImprovementActionInput(
    string Title, string? RelatedArea, string? Details, string? Owner, DateTimeOffset? TargetDateUtc,
    ImprovementActionStatus Status = ImprovementActionStatus.Open, string? OutcomeNote = null);

/// <summary>Which actions the cross-case register lists.</summary>
public enum RegisterScope { Open, PastTarget, Closed, All }

public sealed record RegisterFilter(
    RegisterScope Scope = RegisterScope.Open, string? Search = null, bool IncludeExercises = false);

/// <summary>A register row: the action plus the case it came from.</summary>
public sealed record ImprovementActionRegisterRow(
    ImprovementActionView Action, string CaseNumber, string CaseTitle, Classification? Classification, bool IsExercise);

/// <summary>Program-level counts across every visible case (independent of the scope filter).</summary>
public sealed record RegisterSummary(int Open, int PastTarget, int CompletedLast12Months, int NotPursuedLast12Months);

public sealed record ImprovementActionRegister(IReadOnlyList<ImprovementActionRegisterRow> Rows, RegisterSummary Summary);

/// <summary>
/// Post-incident review + improvement-action register (E-26 / PROD-41). Per case: one structured
/// lessons-learned review and any number of improvement actions it identified. Across cases: the register of
/// actions, tracked to closure — evidence for the NYDFS 500.04 board report and the 500.17 certification.
/// Wording is neutral by design (these records are discoverable); see <see cref="PostIncidentReview"/>.
/// <para>
/// Stance: capture and track only. Every change is an attributable human edit, audited and hash-chained by
/// the save interceptor; nothing here changes case state or acts automatically. Writes require
/// <see cref="Permission.EditCases"/> (asserted here, not just in the UI — the F-21 backstop), and every
/// read and write is need-to-know scoped to cases the caller can see. Editing stays open after a case closes,
/// because follow-up work routinely outlives the case.
/// </para>
/// </summary>
public sealed class LessonsService
{
    private const int MaxText = 4000;

    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly IUserDirectory _users;
    private readonly Content.IMarkdownService _markdown;

    public LessonsService(IAppDbContextFactory factory, ICurrentUser user, IClock clock, IUserDirectory users,
        Content.IMarkdownService markdown)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _users = users;
        _markdown = markdown;
    }

    // ---- Per case ----------------------------------------------------------------------------------

    /// <summary>The review and actions for a case the caller can see; an empty view otherwise (no existence leak).</summary>
    public async Task<CaseLessonsView> GetForCaseAsync(Guid caseId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        if (!await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct))
            return new CaseLessonsView(null, []);

        var review = await db.PostIncidentReviews.AsNoTracking().FirstOrDefaultAsync(r => r.CaseId == caseId, ct);
        var actions = await db.ImprovementActions.AsNoTracking().Where(a => a.CaseId == caseId).ToListAsync(ct);
        var now = _clock.UtcNow;

        return new CaseLessonsView(
            review is null ? null : ToView(review),
            Ordered(actions).Select(a => ToView(a, now)).ToList());
    }

    /// <summary>
    /// Creates or updates the case's review. <paramref name="expectedStamp"/> is the <see cref="PostIncidentReviewView.Stamp"/>
    /// the editor loaded (null for a first save); if another author saved in between, the save is refused with
    /// <see cref="StaleEditException"/> rather than silently overwriting their text (FR-06).
    /// </summary>
    public async Task SaveReviewAsync(Guid caseId, PostIncidentReviewInput input, string? expectedStamp,
        CancellationToken ct = default)
    {
        Require(Permission.EditCases);
        var happened = Clean(input.WhatHappened, "What happened");
        var factors = Clean(input.ContributingFactors, "Contributing factors");
        var worked = Clean(input.WhatWorkedWell, "What worked well");
        var improve = Clean(input.OpportunitiesToImprove, "Opportunities to improve");

        using var db = _factory.CreateDbContext();
        await LoadCaseTrackedAsync(db, caseId, ct);
        var review = await db.PostIncidentReviews.FirstOrDefaultAsync(r => r.CaseId == caseId, ct);

        var currentStamp = review is null ? "" : StampOf(review);
        if ((expectedStamp ?? "") != currentStamp)
            throw new StaleEditException(currentStamp,
                "Someone else saved this review while you were editing. Reload to see their changes.");

        if (input.NoActionsIdentified
            && await db.ImprovementActions.AnyAsync(a => a.CaseId == caseId && a.Status != ImprovementActionStatus.NotPursued, ct))
            throw new ArgumentException(
                "This case has improvement actions logged, so it can't also be marked \"no improvement actions identified\".");

        var now = _clock.UtcNow;
        if (review is null)
        {
            review = new PostIncidentReview { CaseId = caseId, CreatedBy = _user.UserId, CreatedAtUtc = now };
            db.PostIncidentReviews.Add(review);
        }
        else
        {
            review.ModifiedBy = _user.UserId;
            review.ModifiedAtUtc = now;
        }
        review.WhatHappened = happened;
        review.ContributingFactors = factors;
        review.WhatWorkedWell = worked;
        review.OpportunitiesToImprove = improve;
        review.NoActionsIdentified = input.NoActionsIdentified;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Logs an improvement action against a case. Logging one answers the review's follow-up question, so an
    /// earlier "no improvement actions identified" is cleared in the same audited save.
    /// </summary>
    public async Task<Guid> AddActionAsync(Guid caseId, ImprovementActionInput input, CancellationToken ct = default)
    {
        Require(Permission.EditCases);
        var v = Validate(input);

        using var db = _factory.CreateDbContext();
        await LoadCaseTrackedAsync(db, caseId, ct);
        var now = _clock.UtcNow;
        var action = new ImprovementAction
        {
            CaseId = caseId, Title = v.Title, RelatedArea = v.RelatedArea, Details = v.Details,
            Owner = v.Owner, TargetDateUtc = input.TargetDateUtc, Status = input.Status,
            ClosedAtUtc = input.Status.IsClosed() ? now : null, OutcomeNote = v.OutcomeNote,
            CreatedBy = _user.UserId, CreatedAtUtc = now
        };
        db.ImprovementActions.Add(action);

        var review = await db.PostIncidentReviews.FirstOrDefaultAsync(r => r.CaseId == caseId, ct);
        if (review is { NoActionsIdentified: true })
        {
            review.NoActionsIdentified = false;
            review.ModifiedBy = _user.UserId;
            review.ModifiedAtUtc = now;
        }

        await db.SaveChangesAsync(ct);
        return action.Id;
    }

    /// <summary>
    /// Edits an action in one audited change. Moving to a closed status stamps <see cref="ImprovementAction.ClosedAtUtc"/>
    /// (kept if it was already closed); reopening clears it so the action re-enters the open register.
    /// </summary>
    public async Task UpdateActionAsync(Guid caseId, Guid actionId, ImprovementActionInput input, CancellationToken ct = default)
    {
        Require(Permission.EditCases);
        var v = Validate(input);

        using var db = _factory.CreateDbContext();
        await LoadCaseTrackedAsync(db, caseId, ct);
        var action = await db.ImprovementActions.FirstOrDefaultAsync(a => a.Id == actionId && a.CaseId == caseId, ct)
                     ?? throw new InvalidOperationException("Improvement action not found.");

        var now = _clock.UtcNow;
        action.Title = v.Title;
        action.RelatedArea = v.RelatedArea;
        action.Details = v.Details;
        action.Owner = v.Owner;
        action.TargetDateUtc = input.TargetDateUtc;
        action.ClosedAtUtc = input.Status.IsClosed() ? (action.IsClosed ? action.ClosedAtUtc : now) : null;
        action.Status = input.Status;
        action.OutcomeNote = v.OutcomeNote;
        action.ModifiedBy = _user.UserId;
        action.ModifiedAtUtc = now;
        await db.SaveChangesAsync(ct);
    }

    // ---- Cross-case register -----------------------------------------------------------------------

    /// <summary>
    /// The improvement-action register across every case the caller can see. Exercise (tabletop) cases are
    /// left out unless asked for, like every other org-posture surface (PROD-43). The summary counts ignore the
    /// scope and search filters so the headline numbers stay stable while browsing.
    /// </summary>
    public async Task<ImprovementActionRegister> GetRegisterAsync(RegisterFilter filter, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var cases = db.Cases.AsNoTracking().ForUser(_user);
        if (!filter.IncludeExercises) cases = cases.ExcludingExercises();

        var rows = await (
                from a in db.ImprovementActions.AsNoTracking()
                join c in cases on a.CaseId equals c.Id
                select new { Action = a, c.CaseNumber, c.Title, c.Classification, c.IsExercise })
            .ToListAsync(ct);

        var now = _clock.UtcNow;
        var yearAgo = now.AddMonths(-12);
        var summary = new RegisterSummary(
            Open: rows.Count(r => !r.Action.IsClosed),
            PastTarget: rows.Count(r => r.Action.IsPastTarget(now)),
            CompletedLast12Months: rows.Count(r => r.Action.Status == ImprovementActionStatus.Completed && r.Action.ClosedAtUtc >= yearAgo),
            NotPursuedLast12Months: rows.Count(r => r.Action.Status == ImprovementActionStatus.NotPursued && r.Action.ClosedAtUtc >= yearAgo));

        var search = filter.Search?.Trim();
        var list = rows
            .Where(r => filter.Scope switch
            {
                RegisterScope.Open => !r.Action.IsClosed,
                RegisterScope.PastTarget => r.Action.IsPastTarget(now),
                RegisterScope.Closed => r.Action.IsClosed,
                _ => true
            })
            .Select(r => new ImprovementActionRegisterRow(ToView(r.Action, now), r.CaseNumber, r.Title, r.Classification, r.IsExercise))
            .Where(r => string.IsNullOrEmpty(search) || Matches(r, search))
            .OrderBy(r => r.Action.Status.IsClosed())
            .ThenBy(r => r.Action.TargetDateUtc ?? DateTimeOffset.MaxValue)
            .ThenBy(r => r.CaseNumber, StringComparer.Ordinal)
            .ToList();

        return new ImprovementActionRegister(list, summary);
    }

    /// <summary>The register as CSV (formula-injection safe, S-01). Markdown fields are flattened to plain text.</summary>
    public async Task<string> ExportRegisterCsvAsync(RegisterFilter filter, CancellationToken ct = default)
    {
        var register = await GetRegisterAsync(filter, ct);
        var sb = new StringBuilder();
        sb.AppendLine("Case,Case title,Exercise,Improvement action,Related area,Details,Owner,Target date (UTC),Status,Past target date,Closed (UTC),Outcome note,Logged (UTC)");
        foreach (var r in register.Rows)
        {
            var a = r.Action;
            sb.AppendLine(string.Join(',', new[]
            {
                r.CaseNumber, r.CaseTitle, r.IsExercise ? "Yes" : "No", a.Title, a.RelatedArea, Plain(a.Details),
                a.OwnerId is null ? "" : a.OwnerName, Date(a.TargetDateUtc), StatusLabel(a.Status), a.IsPastTarget ? "Yes" : "No",
                Date(a.ClosedAtUtc), Plain(a.OutcomeNote), Date(a.CreatedAtUtc)
            }.Select(Csv.Escape)));
        }
        return sb.ToString();
    }

    public static string StatusLabel(ImprovementActionStatus s) => s switch
    {
        ImprovementActionStatus.InProgress => "In progress",
        ImprovementActionStatus.NotPursued => "Not pursued",
        _ => s.ToString()
    };

    /// <summary>Open actions first, then by target date, then by when they were logged — the order every view uses.</summary>
    public static IEnumerable<ImprovementAction> Ordered(IEnumerable<ImprovementAction> actions) =>
        actions.OrderBy(a => a.IsClosed).ThenBy(a => a.TargetDateUtc ?? DateTimeOffset.MaxValue).ThenBy(a => a.CreatedAtUtc);

    // ---- Helpers -----------------------------------------------------------------------------------

    private void Require(Permission permission, [System.Runtime.CompilerServices.CallerMemberName] string action = "")
    {
        if (!_user.Has(permission)) throw new ForbiddenException(permission, action);
    }

    /// <summary>
    /// Tracks the case row (need-to-know scoped) so the audit line for a child write carries its case number.
    /// An invisible case is reported as not found — never as forbidden, which would leak that it exists.
    /// </summary>
    private async Task LoadCaseTrackedAsync(IAppDbContext db, Guid caseId, CancellationToken ct)
    {
        if (await db.Cases.ForUser(_user).FirstOrDefaultAsync(c => c.Id == caseId, ct) is null)
            throw new InvalidOperationException("Case not found.");
    }

    private static (string Title, string? RelatedArea, string? Details, string? Owner, string? OutcomeNote)
        Validate(ImprovementActionInput input)
    {
        var title = (input.Title ?? "").Trim();
        if (title.Length == 0) throw new ArgumentException("Describe the improvement action.");
        if (title.Length > 400) throw new ArgumentException("The improvement action must be 400 characters or fewer.");
        var outcome = Clean(input.OutcomeNote, "Outcome note");
        if (input.Status.IsClosed() && outcome is null)
            throw new ArgumentException(input.Status == ImprovementActionStatus.NotPursued
                ? "Record why this action is not being pursued, and who decided, before closing it."
                : "Add an outcome note describing what was done before closing the action.");
        return (title, Clean(input.RelatedArea, "Related area", 200), Clean(input.Details, "Details"),
            Clean(input.Owner, "Owner", 200), outcome);
    }

    private static string? Clean(string? value, string field, int max = MaxText)
    {
        var v = value?.Trim();
        if (string.IsNullOrEmpty(v)) return null;
        if (v.Length > max) throw new ArgumentException($"{field} must be {max} characters or fewer.");
        return v;
    }

    private static bool Matches(ImprovementActionRegisterRow r, string term) =>
        Contains(r.CaseNumber, term) || Contains(r.CaseTitle, term) || Contains(r.Action.Title, term)
        || Contains(r.Action.RelatedArea, term) || Contains(r.Action.Details, term) || Contains(r.Action.OwnerName, term);

    private string Plain(string? markdown) => string.IsNullOrWhiteSpace(markdown) ? "" : _markdown.ToPlainText(markdown);

    private static bool Contains(string? s, string term) => s?.Contains(term, StringComparison.OrdinalIgnoreCase) == true;

    private static string Date(DateTimeOffset? d) => d?.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "";

    private static string StampOf(PostIncidentReview r) => string.Join('\u001f',
        r.WhatHappened, r.ContributingFactors, r.WhatWorkedWell, r.OpportunitiesToImprove, r.NoActionsIdentified);

    private PostIncidentReviewView ToView(PostIncidentReview r) => new(
        r.WhatHappened, r.ContributingFactors, r.WhatWorkedWell, r.OpportunitiesToImprove, r.NoActionsIdentified, r.IsRecorded,
        _users.DisplayFor(r.ModifiedBy ?? r.CreatedBy), r.ModifiedAtUtc ?? r.CreatedAtUtc, StampOf(r));

    private ImprovementActionView ToView(ImprovementAction a, DateTimeOffset now) => new(
        a.Id, a.CaseId, a.Title, a.RelatedArea, a.Details,
        a.Owner, a.Owner is null ? "Unassigned" : _users.DisplayFor(a.Owner), a.TargetDateUtc, a.Status,
        a.ClosedAtUtc, a.OutcomeNote, a.IsPastTarget(now), a.CreatedAtUtc);
}
