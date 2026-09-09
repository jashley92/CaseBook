using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Access;
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

    public Task RecordCaseOpenAsync(Guid caseId, string caseNumber, bool wasRestricted, CancellationToken ct = default)
    {
        // F-18: stream every access event (independent of the C-05 store's coalescing/scope).
        EmitSiem(AccessType.CaseOpen, caseNumber, wasRestricted, targetId: null, label: null);
        return RecordAsync(AccessType.CaseOpen, caseId, caseNumber, wasRestricted, targetId: null, label: null, ct);
    }

    public async Task RecordArtifactAsync(AccessType type, Guid? caseId, string? label, Guid? targetId = null,
        CancellationToken ct = default)
    {
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

            // Most recent matching open session for this exact (actor, case, type, target).
            var existing = await db.CaseAccessEvents
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
        using var db = _factory.CreateDbContext();
        return await db.CaseAccessEvents.AsNoTracking()
            .Where(e => e.CaseId == caseId && e.AccessType == AccessType.CaseOpen)
            .OrderByDescending(e => e.LastSeenUtc)
            .Take(take)
            .ToListAsync(ct);
    }

    public async Task<IReadOnlyList<string>> ActorsAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await db.CaseAccessEvents.AsNoTracking()
            .Select(e => e.ActorUserId).Distinct().OrderBy(a => a).ToListAsync(ct);
    }
}
