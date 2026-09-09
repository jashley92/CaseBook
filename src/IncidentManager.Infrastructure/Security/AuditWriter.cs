using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// Records a privileged non-mutating action (a read/export) into the hash-chained audit log by
/// appending one <see cref="AuditLogEntry"/> onto the current head. <c>AuditLogEntry</c> is excluded
/// from the interceptor's own auditing, so saving here appends exactly one link and does not recurse.
/// </summary>
public sealed class AuditWriter : IAuditWriter
{
    private readonly IAppDbContext _db;
    private readonly IHashChainService _hasher;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public AuditWriter(IAppDbContext db, IHashChainService hasher, ICurrentUser user, IClock clock)
    {
        _db = db;
        _hasher = hasher;
        _user = user;
        _clock = clock;
    }

    public async Task RecordAsync(AuditAction action, string entityType, string? entityId,
        string? caseNumber, string summary, CancellationToken ct = default)
    {
        var head = await _db.AuditLog.AsNoTracking()
            .OrderByDescending(a => a.Sequence).FirstOrDefaultAsync(ct);

        var entry = new AuditLogEntry
        {
            AtUtc = _clock.UtcNow,
            Actor = _user.IsAuthenticated ? _user.UserId : "system",
            Action = action,
            EntityType = entityType,
            EntityId = entityId,
            CaseNumber = caseNumber,
            Summary = summary
        };
        _hasher.ChainAppend(entry, head);

        _db.AuditLog.Add(entry);
        await _db.SaveChangesAsync(ct);
    }
}
