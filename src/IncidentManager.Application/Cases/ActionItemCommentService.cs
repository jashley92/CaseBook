using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Cases;

/// <summary>A single task-commentary note, resolved for display (author name + timestamp).</summary>
public sealed record ActionItemCommentView(
    Guid Id, Guid ActionItemId, string AuthorUserId, string AuthorName,
    string Body, DateTimeOffset CreatedAtUtc);

/// <summary>
/// Append-only commentary on a case's follow-up tasks (<see cref="ActionItem"/>). A comment is a
/// timestamped, attributed progress/blocker/hand-off note; it is part of the case's tamper-evident record
/// (the save interceptor audits + hash-chains it, since <see cref="ActionItemComment"/> carries a CaseId).
/// Visibility is gated by the case workspace that hosts the Tasks tab, mirroring <see cref="CaseCommentService"/>.
/// </summary>
public sealed class ActionItemCommentService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly IUserDirectory _users;

    public ActionItemCommentService(IAppDbContextFactory factory, ICurrentUser user, IClock clock, IUserDirectory users)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _users = users;
    }

    /// <summary>Every task comment on a case, oldest first (the UI groups them under each task).</summary>
    public async Task<List<ActionItemCommentView>> ListForCaseAsync(Guid caseId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        // S-09: need-to-know — a case the caller can't see has no visible task comments.
        if (!await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct)) return [];
        var rows = await db.ActionItemComments.AsNoTracking()
            .Where(c => c.CaseId == caseId)
            .OrderBy(c => c.CreatedAtUtc)
            .ToListAsync(ct);

        return rows.Select(c => new ActionItemCommentView(
            c.Id, c.ActionItemId, c.CreatedBy, _users.DisplayFor(c.CreatedBy),
            c.Body, c.CreatedAtUtc)).ToList();
    }

    /// <summary>Posts a comment on a task. Append-only; returns the new id.</summary>

    /// <summary>
    /// S-16: commenting needs <see cref="Permission.ViewCases"/> — deliberately not EditCases. Discussion is open to
    /// everyone who can see the case, view-only roles included (a manager asking a question, a hand-off note), while
    /// changes to the case record stay with editors. Need-to-know scoping (who can see the case) applies on top.
    /// </summary>
    private void RequireCommenter([System.Runtime.CompilerServices.CallerMemberName] string action = "")
    {
        if (!_user.Has(Permission.ViewCases)) throw new ForbiddenException(Permission.ViewCases, action);
    }

    public async Task<Guid> AddAsync(Guid caseId, Guid actionItemId, string body, CancellationToken ct = default)
    {
        RequireCommenter();
        var text = (body ?? "").Trim();
        if (string.IsNullOrWhiteSpace(text)) throw new ArgumentException("A comment can't be empty.");
        if (text.Length > 8000) throw new ArgumentException("A comment must be 8000 characters or fewer.");

        using var db = _factory.CreateDbContext();

        // Track the case row (no includes) so the save interceptor stamps the audit line with its case
        // number — mirrors CaseCommentService. Cheap: no aggregate load.
        // S-09: scoped, so a comment can't land on a case the caller can't see.
        var caseRow = await db.Cases.ForUser(_user).FirstOrDefaultAsync(c => c.Id == caseId, ct)
                      ?? throw new InvalidOperationException("Case not found or not accessible.");

        // The task must exist and belong to the case (which the hosting workspace has already gated).
        var exists = await db.ActionItems.AsNoTracking()
            .AnyAsync(a => a.Id == actionItemId && a.CaseId == caseId, ct);
        if (!exists) throw new InvalidOperationException("Task not found.");

        var comment = new ActionItemComment
        {
            ActionItemId = actionItemId,
            CaseId = caseId,
            Body = text,
            CreatedBy = _user.UserId,
            CreatedAtUtc = _clock.UtcNow,
        };
        db.ActionItemComments.Add(comment);
        await db.SaveChangesAsync(ct);
        return comment.Id;
    }
}
