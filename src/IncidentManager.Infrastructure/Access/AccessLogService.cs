using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Access;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Common;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace IncidentManager.Infrastructure.Access;

/// <summary>
/// Records and queries the out-of-chain access log (C-05). Writes coalesce into a per-(actor, case,
/// type, target) view-session inside the configured window. Every record path is best-effort and
/// swallows its own failures — access logging must never break opening a case or downloading a file.
///
/// The rows are written through the audit-chain-decorated context, but <see cref="CaseAccessEvent"/> is
/// in the interceptor's <c>NotAudited</c> set, so a save that only touches the access log produces no
/// chain entries and leaves the tamper-evident record untouched.
/// </summary>
public sealed class AccessLogService : IAccessLogService
{
    private readonly IAppDbContextFactory _factory;
    private readonly IAccessLogPolicy _policy;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ISecurityEventSink _siem;
    private readonly ILogger<AccessLogService> _logger;

    public AccessLogService(IAppDbContextFactory factory, IAccessLogPolicy policy, ICurrentUser user,
        IClock clock, ISecurityEventSink siem, ILogger<AccessLogService> logger)
    {
        _factory = factory;
        _policy = policy;
        _user = user;
        _clock = clock;
        _siem = siem;
        _logger = logger;
    }

    public Task RecordCaseOpenAsync(Guid caseId, string caseNumber, bool wasRestricted, bool stillOpen = false,
        CancellationToken ct = default)
    {
        // REV-21: one open of a page builds the workspace more than once (the prerender, then the live page, and again if
        // the layout redraws it), each a fresh component that can't know the others recorded it. The same person opening
        // the same case within a few seconds is that one open: not another SIEM event, not another view in the count.
        if (_user.IsAuthenticated && SameOpen(_user.UserId, caseId, _clock.UtcNow)) return Task.CompletedTask;
        // F-18: stream every access event (independent of the C-05 store's coalescing/scope). BUG-243: an open, not
        // every reload of a case already open.
        if (!stillOpen) EmitSiem(AccessType.CaseOpen, caseNumber, wasRestricted, targetId: null, label: null);
        return RecordAsync(AccessType.CaseOpen, caseId, caseNumber, wasRestricted, targetId: null, label: null, ct);
    }

    internal static readonly TimeSpan SameOpenWindow = TimeSpan.FromSeconds(15);
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<(string User, Guid Case), DateTimeOffset> RecentOpens = new();

    // True when this person's last recorded open of this case was moments ago; otherwise remembers this one.
    private static bool SameOpen(string user, Guid caseId, DateTimeOffset now)
    {
        var key = (user, caseId);
        if (RecentOpens.TryGetValue(key, out var last) && now - last < SameOpenWindow && now >= last) return true;
        RecentOpens[key] = now;
        if (RecentOpens.Count > 2048)
            foreach (var old in RecentOpens.Where(kv => now - kv.Value > SameOpenWindow).Select(kv => kv.Key).ToList())
                RecentOpens.TryRemove(old, out _);
        return false;
    }

    public async Task RecordArtifactAsync(AccessType type, Guid? caseId, string? label, Guid? targetId = null,
        CancellationToken ct = default)
    {
        // The label is outsider-influenced (an uploaded evidence file name reaches here as the label, then
        // flows into the SIEM field, the stored C-05 row, and any diagnostic log below). Flatten it to a
        // single control-char-free line up front so it can never forge a second log line (CWE-117) or
        // corrupt a record — legitimate file names pass through unchanged.
        label = LogSanitizer.Clean(label);
        try
        {
            string? caseNumber = null;
            var wasRestricted = false;
            if (caseId is { } cid)
            {
                using var lookup = _factory.CreateDbContext();
                var c = await lookup.Cases.AsNoTracking()
                    .Where(x => x.Id == cid)
                    .Select(x => new { x.CaseNumber, x.IsRestricted })
                    .FirstOrDefaultAsync(ct);
                caseNumber = c?.CaseNumber;
                wasRestricted = c?.IsRestricted ?? false;
            }

            EmitSiem(type, caseNumber, wasRestricted, targetId, label); // F-18: stream the artifact access
            await RecordAsync(type, caseId, caseNumber, wasRestricted, targetId, label, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Access log: failed to record {AccessType} for case {CaseId}.", type, caseId);
        }
    }

    // F-18: emit a per-event security signal for an access (not coalesced, not gated by the C-05 scope).
    private void EmitSiem(AccessType type, string? caseNumber, bool wasRestricted, Guid? targetId, string? label)
    {
        if (!_user.IsAuthenticated) return;
        _siem.Emit(SecurityEvents.CaseAccess(type, wasRestricted, _user.UserId, _user.UserPrincipalName,
            caseNumber, targetId, label));
    }

    private async Task RecordAsync(AccessType type, Guid? caseId, string? caseNumber, bool wasRestricted,
        Guid? targetId, string? label, CancellationToken ct)
    {
        try
        {
            if (!_user.IsAuthenticated) return;
            if (!_policy.ShouldLog(type, wasRestricted)) return;

            var actor = _user.UserId;
            var now = _clock.UtcNow;

            using var db = _factory.CreateDbContext();

            // Most recent matching open session for this exact (actor, case, type, target). BUG-154: never for an
            // export: each is a deliberate pull of its own data (a slice of the access log, a compliance bundle), and most
            // name no case or target, so folding them kept only the first one's file name.
            var existing = type == AccessType.Export ? null : await db.CaseAccessEvents
                .Where(e => e.ActorUserId == actor
                            && e.CaseId == caseId
                            && e.AccessType == type
                            && e.TargetId == targetId)
                .OrderByDescending(e => e.LastSeenUtc)
                .FirstOrDefaultAsync(ct);

            if (existing is not null && AccessCoalescer.ShouldCoalesce(existing.LastSeenUtc, now, _policy.CoalesceWindow))
                existing.Touch(now);
            else
                db.CaseAccessEvents.Add(
                    CaseAccessEvent.Start(actor, caseId, caseNumber, type, targetId, label, wasRestricted, now));

            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Access log: failed to record {AccessType} for case {CaseId}.", type, caseId);
        }
    }

    public async Task<IReadOnlyList<CaseAccessEvent>> QueryAsync(AccessLogFilter filter, int take = 500, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<IAccessLogService>(_user, _siem);   // who read what: administrators only
        using var db = _factory.CreateDbContext();
        var q = db.CaseAccessEvents.AsNoTracking().AsQueryable();

        if (!string.IsNullOrWhiteSpace(filter.Actor))
            q = q.Where(e => e.ActorUserId == filter.Actor);
        if (!string.IsNullOrWhiteSpace(filter.CaseNumber))
            q = q.Where(e => e.CaseNumber == filter.CaseNumber);
        if (filter.AccessType is { } t)
            q = q.Where(e => e.AccessType == t);
        if (filter.RestrictedOnly)
            q = q.Where(e => e.WasRestricted);
        if (filter.FromUtc is { } from)
            q = q.Where(e => e.LastSeenUtc >= from);
        if (filter.ToUtc is { } to)
            q = q.Where(e => e.LastSeenUtc <= to);

        return await q.OrderByDescending(e => e.LastSeenUtc).Take(take).ToListAsync(ct);
    }

    public async Task<IReadOnlyList<CaseAccessEvent>> ForCaseAsync(Guid caseId, int take = 200, CancellationToken ct = default)
    {
        // BUG-131: who opened a case is shown to roles that see every case (the Audit tab's gate), and only for a case
        // the caller can see; asserted here too, not only by the page.
        if (!_user.Has(Permission.ViewAllCases)) return [];
        using var db = _factory.CreateDbContext();
        if (!await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct)) return [];
        return await db.CaseAccessEvents.AsNoTracking()
            .Where(e => e.CaseId == caseId && e.AccessType == AccessType.CaseOpen)
            .OrderByDescending(e => e.LastSeenUtc)
            .Take(take)
            .ToListAsync(ct);
    }

    public async Task<DateTimeOffset?> LastViewedAsync(Guid caseId, CancellationToken ct = default)
    {
        if (!_user.IsAuthenticated) return null;
        try
        {
            using var db = _factory.CreateDbContext();
            var me = _user.UserId;
            var sessions = (await db.CaseAccessEvents.AsNoTracking()
                    .Where(e => e.CaseId == caseId && e.ActorUserId == me && e.AccessType == AccessType.CaseOpen)
                    .Select(e => new { e.FirstSeenUtc, e.LastSeenUtc })
                    .ToListAsync(ct))
                .OrderByDescending(e => e.LastSeenUtc).ToList();
            if (sessions.Count == 0) return null;

            // The page loads twice (server prerender, then interactive), and the first pass already recorded this
            // visit. A session started moments ago is this visit, so the one before it is the last view; a longer
            // session still being extended means the viewer never left, so there's nothing "since" to show.
            var recent = _clock.UtcNow - TimeSpan.FromMinutes(1);
            var latest = sessions[0];
            if (latest.FirstSeenUtc > recent) return sessions.Count > 1 ? sessions[1].LastSeenUtc : null;
            return latest.LastSeenUtc > recent ? null : latest.LastSeenUtc;
        }
        catch (Exception)
        {
            return null; // best-effort, like recording: a lookup failure never blocks opening a case
        }
    }

    public async Task<IReadOnlyList<string>> ActorsAsync(CancellationToken ct = default)
    {
        AdminActionPermissions.Require<IAccessLogService>(_user, _siem);
        using var db = _factory.CreateDbContext();
        return await db.CaseAccessEvents.AsNoTracking()
            .Select(e => e.ActorUserId).Distinct().OrderBy(a => a).ToListAsync(ct);
    }
}
