using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Cases;

/// <summary>A case discussion comment, resolved for display (author + mention names).</summary>
public sealed record CaseCommentView(
    Guid Id, Guid? ParentId, string AuthorUserId, string AuthorName,
    string Body, IReadOnlyList<string> Mentions, DateTimeOffset CreatedAtUtc);

/// <summary>
/// Durable, threaded case discussion (PROD-04). Comments are append-only and part of the case's
/// tamper-evident record (the save interceptor audits + hash-chains them, since a <see cref="CaseComment"/>
/// is a domain entity carrying a CaseId). Posting a comment that @mentions teammates notifies them through
/// the notification pipeline (email + optional chat). Visibility is gated by the case workspace that hosts
/// the tab, mirroring how notes are handled.
/// </summary>
public sealed class CaseCommentService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly IUserDirectory _users;
    private readonly ICaseNotifications _notifications;

    public CaseCommentService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        IUserDirectory users, ICaseNotifications notifications)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _users = users;
        _notifications = notifications;
    }

    /// <summary>Every comment on a case, oldest first (the UI threads replies under their parent).</summary>
    public async Task<List<CaseCommentView>> ListAsync(Guid caseId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        // S-09: need-to-know — a case the caller can't see has no visible discussion.
        if (!await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct)) return [];
        var rows = await db.CaseComments.AsNoTracking()
            .Where(c => c.CaseId == caseId)
            .OrderBy(c => c.CreatedAtUtc)
            .ToListAsync(ct);

        return rows.Select(c => new CaseCommentView(
            c.Id, c.ParentId, c.CreatedBy, _users.DisplayFor(c.CreatedBy),
            c.Body, ResolveMentions(c.MentionsCsv), c.CreatedAtUtc)).ToList();
    }

    /// <summary>
    /// Posts a comment (optionally a reply, and optionally @mentioning teammates). Returns the new id.
    /// Replies are normalised to a single level. Mentioned users are notified after the comment persists.
    /// </summary>
    public async Task<Guid> AddAsync(Guid caseId, string body, Guid? parentId,
        IReadOnlyCollection<string>? mentionUserIds, CancellationToken ct = default)
    {
        var text = (body ?? "").Trim();
        if (string.IsNullOrWhiteSpace(text)) throw new ArgumentException("A comment can't be empty.");
        if (text.Length > 8000) throw new ArgumentException("A comment must be 8000 characters or fewer.");

        using var db = _factory.CreateDbContext();

        // Track the case row (no includes) so the audit line carries its case number, and so we have the
        // case fields for the mention notification. Cheap — no aggregate load.
        // S-09: scoped, so a comment can't land on a case the caller can't see.
        var caseRow = await db.Cases.ForUser(_user).FirstOrDefaultAsync(c => c.Id == caseId, ct)
                      ?? throw new InvalidOperationException("Case not found or not accessible.");

        // Normalise a reply to one level: a reply to a reply attaches to the top-level thread.
        Guid? effectiveParent = null;
        if (parentId is { } pid)
        {
            var parent = await db.CaseComments.AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == pid && c.CaseId == caseId, ct);
            if (parent is not null) effectiveParent = parent.ParentId ?? parent.Id;
        }

        // De-dupe mentions and drop the author (you don't get notified for mentioning yourself).
        var mentions = (mentionUserIds ?? [])
            .Where(id => !string.IsNullOrWhiteSpace(id) && !string.Equals(id, _user.UserId, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var comment = new CaseComment
        {
            CaseId = caseId,
            ParentId = effectiveParent,
            Body = text,
            MentionsCsv = string.Join(',', mentions),
            CreatedBy = _user.UserId,
            CreatedAtUtc = _clock.UtcNow,
        };
        db.CaseComments.Add(comment);
        await db.SaveChangesAsync(ct);

        if (mentions.Count > 0)
            await _notifications.OnMentionedAsync(caseRow, _user.UserId, mentions, text, ct);

        return comment.Id;
    }

    private List<string> ResolveMentions(string? csv) =>
        string.IsNullOrWhiteSpace(csv)
            ? []
            : csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                 .Select(_users.DisplayFor).ToList();
}
