using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Application.Work;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>CAP-30: an open case the leaver commands or is on, as the administrator may see it.</summary>
public sealed record OffboardingCaseRow(Guid CaseId, string CaseNumber, string Title, CasePhase Phase, bool Commands,
    bool IsRestricted, bool IsExercise);

/// <summary>CAP-30: an open task the leaver owns, on a case the administrator may see.</summary>
public sealed record OffboardingTaskRow(Guid TaskId, Guid CaseId, string CaseNumber, string Title, DateTimeOffset? DueAtUtc);

/// <summary>CAP-30: one of the leaver's personal API tokens that works now. Never the token itself: its prefix only.</summary>
public sealed record OffboardingTokenRow(Guid TokenId, string Name, string Prefix, DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc, DateTimeOffset? LastUsedAtUtc);

/// <summary>
/// CAP-30: everything about one person an administrator needs when they leave. <see cref="HiddenCases"/> and
/// <see cref="HiddenTasks"/> count what's outside the administrator's own need-to-know (a restricted case without
/// <c>ViewRestricted</c>), so the page says it's there without naming it. The calendar link is never shown, only whether
/// one works.
/// </summary>
public sealed record OffboardingView(
    Guid UserRef,
    string DisplayName,
    string? UserPrincipalName,
    IReadOnlyList<string> Roles,
    DateTimeOffset LastSeenUtc,
    bool IsDormant,
    IReadOnlyList<OffboardingCaseRow> Cases,
    int HiddenCases,
    IReadOnlyList<OffboardingTaskRow> Tasks,
    int HiddenTasks,
    IReadOnlyList<OffboardingTokenRow> Tokens,
    int SystemTokensCreated,
    bool CalendarFeedOn,
    bool CalendarLinkLive,
    DateTimeOffset? CalendarLinkExpiresAtUtc);

/// <summary>
/// CAP-30: the offboarding page for a person who leaves, opened from Known users in the access review. What used to be
/// on four screens in one place: the roles AD gave them at their last sign-in (AD stays the source; nothing here changes
/// a role), the open cases they command or are on, their open tasks, their working API tokens and whether their calendar
/// link works; and the two things CaseBook itself can take back: their tokens (revoked) and their calendar link (voided,
/// a new administrator path, the link never shown). Reassigning their cases stays in Team workload's limited reassign.
/// <c>Administer</c> for all of it; each action is in the audit trail. The person is named by their <c>AppUser</c> row's
/// id, an opaque reference, so no name or account is in the page's address.
/// </summary>
public sealed class OffboardingService(
    IAppDbContextFactory factory,
    ICurrentUser user,
    IClock clock,
    IAuditWriter audit,
    IAgendaFeedTokens? feeds = null,
    ISecurityEventSink? siem = null)
{
    /// <summary>The audit trail's entity type for an offboarding action (the entity id is the person's reference).</summary>
    public const string AuditEntityType = "Offboarding";

    /// <summary>Everything the page shows, or null when no such person has signed in.</summary>
    public async Task<OffboardingView?> BuildAsync(Guid userRef, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<OffboardingService>(user, siem);
        using var db = factory.CreateDbContext();
        var person = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userRef, ct);
        if (person is null || string.Equals(person.Sid, "system", StringComparison.OrdinalIgnoreCase)) return null;
        var sid = person.Sid;
        var now = clock.UtcNow;
        var roleNames = (await db.Roles.AsNoTracking().Select(r => r.Name).ToListAsync(ct)).ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Open cases they command or are on: listed through the administrator's own need-to-know (P3), the rest counted.
        var theirs = db.Cases.AsNoTracking()
            .Where(c => !c.IsArchived && c.Phase != CasePhase.Closed
                        && (c.IncidentCommander == sid || c.Assignments.Any(a => a.UserId == sid)));
        var cases = await theirs.ForUser(user)
            .OrderBy(c => c.CaseNumber)
            .Select(c => new OffboardingCaseRow(c.Id, c.CaseNumber, c.Title, c.Phase, c.IncidentCommander == sid, c.IsRestricted, c.IsExercise))
            .ToListAsync(ct);
        var hiddenCases = await theirs.CountAsync(ct) - cases.Count;

        // Open tasks they own (the owner is free text: their id, name, address or UPN), on open cases.
        var ids = new[] { sid, person.DisplayName, person.UserPrincipalName, person.Email };
        var openTasks = db.ActionItems.AsNoTracking()
            .Where(a => a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled && a.Owner != null);
        var visibleTasks = (await (from a in openTasks
                                   join c in db.Cases.AsNoTracking().ForUser(user) on a.CaseId equals c.Id
                                   where !c.IsArchived && c.Phase != CasePhase.Closed
                                   select new { a.Id, a.CaseId, c.CaseNumber, a.Title, a.DueAtUtc, a.Owner })
                .ToListAsync(ct))
            .Where(t => TaskOwner.Matches(t.Owner, ids))
            .OrderBy(t => t.DueAtUtc ?? DateTimeOffset.MaxValue).ThenBy(t => t.CaseNumber, StringComparer.OrdinalIgnoreCase)
            .Select(t => new OffboardingTaskRow(t.Id, t.CaseId, t.CaseNumber, t.Title, t.DueAtUtc))
            .ToList();
        var allTaskOwners = await (from a in openTasks
                                   join c in db.Cases.AsNoTracking() on a.CaseId equals c.Id
                                   where !c.IsArchived && c.Phase != CasePhase.Closed
                                   select a.Owner).ToListAsync(ct);
        var hiddenTasks = allTaskOwners.Count(o => TaskOwner.Matches(o, ids)) - visibleTasks.Count;

        var tokens = await db.ApiTokens.AsNoTracking()
            .Where(t => t.Kind == ApiTokenKind.Personal && t.OwnerUserId == sid && t.RevokedAtUtc == null && t.ExpiresAtUtc > now)
            .OrderBy(t => t.CreatedAtUtc)
            .Select(t => new OffboardingTokenRow(t.Id, t.Name, t.Prefix, t.CreatedAtUtc, t.ExpiresAtUtc, t.LastUsedAtUtc))
            .ToListAsync(ct);
        var systemTokens = await db.ApiTokens.AsNoTracking()
            .CountAsync(t => t.Kind == ApiTokenKind.System && t.CreatedBy == sid && t.RevokedAtUtc == null && t.ExpiresAtUtc > now, ct);

        var feedOn = feeds?.Enabled ?? false;
        DateTimeOffset? linkExpires = person.FeedLinkIssuedAtUtc is { } issued ? issued + AgendaFeedService.MaxAge : null;
        var linkLive = linkExpires is { } until && until > now;

        return new OffboardingView(person.Id,
            string.IsNullOrWhiteSpace(person.DisplayName) ? sid : person.DisplayName,
            string.IsNullOrWhiteSpace(person.UserPrincipalName) ? null : person.UserPrincipalName,
            Domain.Common.RoleList.Split(person.RolesCsv, roleNames.Contains),
            person.LastSeenUtc, now - person.LastSeenUtc > AccessReviewService.DormantAfter,
            cases, Math.Max(0, hiddenCases), visibleTasks, Math.Max(0, hiddenTasks), tokens, systemTokens,
            feedOn, linkLive, linkLive ? linkExpires : null);
    }

    /// <summary>
    /// Revokes the leaver's personal tokens the page listed (<paramref name="tokenIds"/>, C9: what the administrator saw),
    /// in one save; one revoked meanwhile, or that isn't theirs, is left out. Returns how many were revoked. Each is in the
    /// audit trail as a revocation (the token's row is chained) and on the SIEM, and the action as a whole once more.
    /// </summary>
    public async Task<int> RevokeTokensAsync(Guid userRef, IReadOnlyCollection<Guid> tokenIds, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<OffboardingService>(user, siem);
        ArgumentNullException.ThrowIfNull(tokenIds);
        if (tokenIds.Count == 0) throw new InvalidOperationException("There are no tokens to revoke.");
        using var db = factory.CreateDbContext();
        var person = await PersonAsync(db, userRef, ct);
        var now = clock.UtcNow;
        var ids = tokenIds.Distinct().ToList();
        var rows = await db.ApiTokens
            .Where(t => ids.Contains(t.Id) && t.Kind == ApiTokenKind.Personal && t.OwnerUserId == person.Sid && t.RevokedAtUtc == null)
            .ToListAsync(ct);
        if (rows.Count == 0)
            throw new InvalidOperationException("Those tokens are no longer working (revoked or expired since you opened the page), so nothing changed.");
        foreach (var row in rows)
        {
            row.RevokedAtUtc = now;
            row.RevokedBy = user.UserId;
        }
        await db.SaveChangesAsync(ct);   // REV-05: each revocation chained, all in the same save
        foreach (var row in rows)
            siem?.Emit(SecurityEvents.ApiTokenChanged("ApiTokenRevoked", user.UserId, user.UserPrincipalName, $"{row.Name} ({row.Kind})"));
        await audit.RecordAsync(AuditAction.Update, AuditEntityType, person.Id.ToString(), null,
            $"Offboarding {Named(person)}: revoked {Common.Plural.Of(rows.Count, "API token")} ({string.Join(", ", rows.Select(r => r.Prefix))}).", ct);
        return rows.Count;
    }

    /// <summary>
    /// Voids the leaver's calendar (agenda feed) link, so a subscribed calendar stops getting their cases at its next
    /// refresh. A new administrator path (the user's own reset stays on their account page); the link is never read or
    /// shown. If they sign in again later, they get a new link only by asking for one. Audited.
    /// </summary>
    public async Task VoidCalendarLinkAsync(Guid userRef, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<OffboardingService>(user, siem);
        using var db = factory.CreateDbContext();
        var person = await PersonAsync(db, userRef, ct);
        if (person.FeedLinkIssuedAtUtc is not { } issued || issued + AgendaFeedService.MaxAge <= clock.UtcNow)
            throw new InvalidOperationException($"{Named(person)} has no calendar link that works, so there's nothing to void.");
        person.FeedLinkIssuedAtUtc = null;   // AgendaFeedService.ResolveAsync then refuses every link issued before
        await db.SaveChangesAsync(ct);
        await audit.RecordAsync(AuditAction.Update, AuditEntityType, person.Id.ToString(), null,
            $"Offboarding {Named(person)}: voided their calendar link.", ct);
    }

    private static async Task<Domain.Entities.AppUser> PersonAsync(IAppDbContext db, Guid userRef, CancellationToken ct)
    {
        var person = await db.Users.FirstOrDefaultAsync(u => u.Id == userRef, ct);
        if (person is null || string.Equals(person.Sid, "system", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("That person isn't in CaseBook's list of people who have signed in.");
        return person;
    }

    private static string Named(Domain.Entities.AppUser person) =>
        string.IsNullOrWhiteSpace(person.DisplayName) ? person.Sid : $"{person.DisplayName} ({person.Sid})";
}
