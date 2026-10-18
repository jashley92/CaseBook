using System.Globalization;
using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using static IncidentManager.Application.Common.Csv;

namespace IncidentManager.Application.Admin;

/// <summary>A role that can see across cases, and the AD groups that confer it.</summary>
public sealed record BroadAccessRow(string RoleName, bool ViewAllCases, bool ViewRestricted, IReadOnlyList<string> Groups);

/// <summary>A restricted case and the individuals with case-specific need-to-know.</summary>
public sealed record RestrictedCaseRow(string CaseNumber, string Title, string? IncidentCommander, IReadOnlyList<string> Assignees,
    bool IsArchived = false);

/// <summary>
/// A person CaseBook has seen sign in (the <c>AppUser</c> mirror), with the roles AD granted them at that
/// sign-in. <see cref="IsDormant"/> flags accounts idle past <see cref="AccessReviewService.DormantAfter"/>.
/// </summary>
public sealed record KnownUserRow(string DisplayName, string? UserPrincipalName, IReadOnlyList<string> Roles,
    DateTimeOffset LastSeenUtc, bool IsDormant);

/// <summary>CAP-15: an API token that works now (not revoked, not expired), with the roles it was granted. A personal
/// token also acts only within its owner's current roles.</summary>
public sealed record ApiTokenReviewRow(string Name, ApiTokenKind Kind, string Owner, string Prefix, IReadOnlyList<string> Roles,
    DateTimeOffset CreatedAtUtc, DateTimeOffset ExpiresAtUtc, DateTimeOffset? LastUsedAtUtc);

public sealed record AccessReview(IReadOnlyList<BroadAccessRow> Broad, IReadOnlyList<RestrictedCaseRow> RestrictedCases,
    IReadOnlyList<KnownUserRow> KnownUsers, IReadOnlyList<ApiTokenReviewRow> ApiTokens);

/// <summary>CAP-15: a recorded access review: who recorded it, when, and their note. Read back from the audit trail.</summary>
public sealed record AccessReviewRecord(DateTimeOffset AtUtc, string ReviewerId, string Reviewer, string Note);

/// <summary>CAP-15: whether the next access review is due. <see cref="Off"/> when the reminder is 0 days.</summary>
public sealed record AccessReviewReminder(bool Off, bool Due, DateTimeOffset? DueAtUtc);

/// <summary>CAP-15: the access-review reminder, bound from <c>Governance:AccessReview</c>.</summary>
public sealed class AccessReviewOptions
{
    /// <summary>Days after a recorded review before Diagnostics reminds that the next is due. 0 turns the reminder off.</summary>
    public int ReminderDays { get; set; } = 90;
}

/// <summary>
/// A need-to-know review for auditors (NYDFS): who can currently see restricted cases and
/// why. Broad access comes from roles granting <see cref="Permission.ViewAllCases"/> /
/// <see cref="Permission.ViewRestricted"/> (and the AD groups mapped to them); case-specific access is
/// the incident commander plus assignees. Mirrors the scoping in <c>CaseQueryExtensions.ForUser</c>.
/// PROD-14: also lists everyone who has signed in, with their roles as of that sign-in and when they were
/// last seen, so a periodic user-access review (NYDFS 500.7) can spot dormant accounts that still hold roles.
/// Roles here are a snapshot: AD is the source of truth, and changes take effect at the user's next sign-in.
/// CAP-15: also the API tokens that work now, a CSV of the whole review, and "Record this review": the reviewer's note,
/// kept as an entry in the audit trail (so it's chained and sealed like every other record, and can't be edited after),
/// with a reminder in Diagnostics when the last one is older than <c>Governance:AccessReview:ReminderDays</c>.
/// </summary>
public sealed class AccessReviewService
{
    /// <summary>Accounts not seen for this long are flagged dormant in the review.</summary>
    public static readonly TimeSpan DormantAfter = TimeSpan.FromDays(90);

    /// <summary>CAP-15: the audit trail's name for a recorded review. Nothing else is audited under it.</summary>
    public const string AuditEntityType = "AccessReview";

    /// <summary>CAP-15: the longest note a recorded review takes (its audit entry's summary holds it whole).</summary>
    public const int MaxNoteLength = 1000;

    /// <summary>CAP-15: the longest reminder interval the settings page allows; a larger value in the file counts as this.</summary>
    public const int MaxReminderDays = 730;

    private const string NotePrefix = "Access review recorded: ";

    private readonly IAppDbContextFactory _factory;
    private readonly IClock _clock;
    private readonly ICurrentUser _user;
    private readonly ISecurityEventSink? _siem;
    private readonly IAuditWriter? _audit;
    private readonly IUserDirectory? _users;
    private readonly IOptionsMonitor<AccessReviewOptions>? _options;

    public AccessReviewService(IAppDbContextFactory factory, IClock clock, ICurrentUser user, ISecurityEventSink? siem = null,
        IAuditWriter? audit = null, IUserDirectory? users = null, IOptionsMonitor<AccessReviewOptions>? options = null)
    {
        _factory = factory;
        _clock = clock;
        _user = user;
        _siem = siem;
        _audit = audit;
        _users = users;
        _options = options;
    }

    /// <summary>CAP-15: the reminder interval now, kept within 0 to <see cref="MaxReminderDays"/> (BUG-262).</summary>
    public int ReminderDays => Math.Clamp(_options?.CurrentValue.ReminderDays ?? 90, 0, MaxReminderDays);

    public async Task<AccessReview> BuildAsync(CancellationToken ct = default)
    {
        AdminActionPermissions.Require<AccessReviewService>(_user, _siem);   // BUG-22: the page is Administer-gated too
        using var db = _factory.CreateDbContext();
        var roles = await db.Roles.AsNoTracking().ToListAsync(ct);
        var maps = await db.RoleMappings.AsNoTracking().ToListAsync(ct);

        var groupsByRole = maps
            .GroupBy(m => m.RoleName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<string>)g.Select(x => x.AdGroup).OrderBy(x => x).ToList(),
                StringComparer.OrdinalIgnoreCase);

        var broad = roles
            .Select(r => (Role: r, Perms: r.GetPermissions()))
            .Where(x => x.Perms.Contains(Permission.ViewAllCases) || x.Perms.Contains(Permission.ViewRestricted))
            .Select(x => new BroadAccessRow(
                x.Role.Name,
                x.Perms.Contains(Permission.ViewAllCases),
                x.Perms.Contains(Permission.ViewRestricted),
                groupsByRole.TryGetValue(x.Role.Name, out var g) ? g : []))
            .OrderByDescending(b => b.ViewAllCases)
            .ThenBy(b => b.RoleName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var cases = await db.Cases.AsNoTracking()
            // REV-58: archived ones too. Archiving doesn't take anyone's access away (its commander and team can still open
            // it), so a need-to-know review that left them out under-stated who can see restricted matters.
            .Where(c => c.IsRestricted)
            .Select(c => new { c.Id, c.CaseNumber, c.Title, c.IncidentCommander, c.IsArchived })
            .OrderBy(c => c.IsArchived).ThenBy(c => c.CaseNumber)
            .ToListAsync(ct);

        var caseIds = cases.Select(c => c.Id).ToList();
        var assignments = await db.Assignments.AsNoTracking()
            .Where(a => caseIds.Contains(a.CaseId))
            .Select(a => new { a.CaseId, a.UserId, a.UserDisplayName })
            .ToListAsync(ct);

        var assigneesByCase = assignments
            .GroupBy(a => a.CaseId)
            .ToDictionary(g => g.Key,
                g => (IReadOnlyList<string>)g.Select(a => a.UserDisplayName ?? a.UserId).Distinct().OrderBy(x => x).ToList());

        var restricted = cases
            .Select(c => new RestrictedCaseRow(
                c.CaseNumber, c.Title, c.IncidentCommander,
                assigneesByCase.TryGetValue(c.Id, out var a) ? a : [], c.IsArchived))
            .ToList();

        var now = _clock.UtcNow;
        var users = await db.Users.AsNoTracking().ToListAsync(ct);
        var roleNames = roles.Select(r => r.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var known = users
            .Where(u => !string.Equals(u.Sid, "system", StringComparison.OrdinalIgnoreCase))
            .Select(u => new KnownUserRow(
                string.IsNullOrWhiteSpace(u.DisplayName) ? u.Sid : u.DisplayName,
                string.IsNullOrWhiteSpace(u.UserPrincipalName) ? null : u.UserPrincipalName,
                Domain.Common.RoleList.Split(u.RolesCsv, roleNames.Contains),   // BUG-591: a legacy name with a comma is one role
                u.LastSeenUtc,
                now - u.LastSeenUtc > DormantAfter))
            .OrderByDescending(u => u.IsDormant)
            .ThenBy(u => u.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        // CAP-15: the API tokens that work now. A system token is a standing machine identity; a personal one acts as its owner.
        var tokens = (await db.ApiTokens.AsNoTracking()
                .Where(t => t.RevokedAtUtc == null && t.ExpiresAtUtc > now)
                .ToListAsync(ct))
            .Select(t => new ApiTokenReviewRow(t.Name, t.Kind, string.IsNullOrWhiteSpace(t.OwnerDisplayName) ? t.OwnerUserId : t.OwnerDisplayName,
                t.Prefix, t.GetRoles(roleNames.Contains), t.CreatedAtUtc, t.ExpiresAtUtc, t.LastUsedAtUtc))
            .OrderBy(t => t.Kind).ThenBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new AccessReview(broad, restricted, known, tokens);
    }

    /// <summary>
    /// CAP-15: records that the access review was done, by the signed-in administrator, now, with their note (what was
    /// looked at, what was changed or raised). An entry in the audit trail, not case data. Returns it as read back.
    /// </summary>
    public async Task<AccessReviewRecord> RecordReviewAsync(string note, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<AccessReviewService>(_user, _siem);
        var text = (note ?? "").Trim();
        if (text.Length == 0) throw new ArgumentException("Say what the review covered and what came of it.");
        if (text.Length > MaxNoteLength) throw new ArgumentException($"Keep the note to {MaxNoteLength:N0} characters or fewer.");
        if (_audit is null) throw new InvalidOperationException("The audit trail isn't available, so the review can't be recorded.");
        await _audit.RecordAsync(AuditAction.Create, AuditEntityType, null, null, NotePrefix + text, ct);
        return await GetLastReviewAsync(ct)
               ?? throw new InvalidOperationException("The review was recorded, but it couldn't be read back.");
    }

    /// <summary>CAP-15: the most recent recorded review, or null when none has been.</summary>
    public async Task<AccessReviewRecord?> GetLastReviewAsync(CancellationToken ct = default)
    {
        AdminActionPermissions.Require<AccessReviewService>(_user, _siem);
        using var db = _factory.CreateDbContext();
        var e = await db.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == AuditEntityType && a.Action == AuditAction.Create)
            .OrderByDescending(a => a.Sequence)
            .Select(a => new { a.AtUtc, a.Actor, a.Summary })
            .FirstOrDefaultAsync(ct);
        if (e is null) return null;
        var summary = e.Summary ?? "";
        var note = summary.StartsWith(NotePrefix, StringComparison.Ordinal) ? summary[NotePrefix.Length..] : summary;
        var reviewer = _users?.DisplayFor(e.Actor) is { Length: > 0 } name ? name : e.Actor;
        return new AccessReviewRecord(e.AtUtc, e.Actor, reviewer, note);
    }

    /// <summary>CAP-15: whether the next review is due, <paramref name="days"/> after <paramref name="last"/>; due at
    /// once when none has been recorded. Off (never due) at 0 days.</summary>
    public static AccessReviewReminder ReminderFor(AccessReviewRecord? last, int days, DateTimeOffset nowUtc)
    {
        if (days <= 0) return new AccessReviewReminder(true, false, null);
        if (last is null) return new AccessReviewReminder(false, true, null);
        var interval = TimeSpan.FromDays(Math.Min(days, MaxReminderDays));
        // C12: a review recorded near the end of time is due at the end of time, not an overflow.
        var due = last.AtUtc > DateTimeOffset.MaxValue - interval ? DateTimeOffset.MaxValue : last.AtUtc + interval;
        return new AccessReviewReminder(false, nowUtc >= due, due);
    }

    /// <summary>
    /// CAP-15: the review as one CSV: a row per broad-access role, restricted case, known user and working API token, each
    /// with its section. Fields go through <c>Csv.Escape</c> (names, titles and AD groups can start with a formula
    /// character). Times are UTC.
    /// </summary>
    public static string ToCsv(AccessReview review, AccessReviewRecord? last, DateTimeOffset generatedAtUtc)
    {
        var inv = CultureInfo.InvariantCulture;
        static string T(DateTimeOffset? t) => t?.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) ?? "";
        var sb = new StringBuilder();
        sb.Append("# CaseBook access review, generated ").Append(generatedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm", inv))
          .Append(" UTC. Times are UTC. Roles are as of each person's last sign-in.\r\n");
        // The last recorded review on a comment line of its own. The note is free text, so the whole line is one escaped
        // field (C13: a quote opens a cell only at its start), on one line.
        sb.Append(Escape("# Last recorded review: " + (last is null ? "none"
            : $"{T(last.AtUtc)} by {last.Reviewer}: {last.Note}".ReplaceLineEndings(" ")))).Append("\r\n");
        sb.Append("section,subject,detail,access,via,last_seen_utc,expires_utc,flag\r\n");
        void Row(params string?[] f) => sb.Append(string.Join(",", f.Select(Escape))).Append("\r\n");

        foreach (var b in review.Broad)
            Row("Broad access", b.RoleName, "",
                string.Join("; ", new[] { b.ViewAllCases ? "All cases" : null, b.ViewRestricted ? "Restricted cases" : null }.OfType<string>()),
                string.Join("; ", b.Groups), "", "", b.Groups.Count == 0 ? "No AD group mapped" : "");
        foreach (var c in review.RestrictedCases)
            Row("Restricted case", c.CaseNumber, c.Title,
                "Incident commander: " + (string.IsNullOrWhiteSpace(c.IncidentCommander) ? "none" : c.IncidentCommander),
                string.Join("; ", c.Assignees), "", "", c.IsArchived ? "Archived" : "");
        foreach (var u in review.KnownUsers)
            Row("Known user", u.DisplayName, u.UserPrincipalName, string.Join("; ", u.Roles), "", T(u.LastSeenUtc), "",
                u.IsDormant ? "Dormant" : "");
        foreach (var t in review.ApiTokens)
            Row("API token", t.Name, $"{(t.Kind == ApiTokenKind.System ? "System" : "Personal")} token of {t.Owner}, starting {t.Prefix}",
                string.Join("; ", t.Roles), "", T(t.LastUsedAtUtc), T(t.ExpiresAtUtc), t.LastUsedAtUtc is null ? "Never used" : "");
        return sb.ToString();
    }
}
