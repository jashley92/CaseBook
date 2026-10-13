using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// Records a privileged non-mutating action (a read/export) into the hash-chained audit log by
/// appending one <see cref="AuditLogEntry"/> onto the current head. <c>AuditLogEntry</c> is excluded
/// from the interceptor's own auditing, so saving here appends exactly one link and does not recurse.
/// BUG-23: each call uses its own context. On the circuit's shared context a failed save left the entry tracked, so
/// every later append in that session re-sent it and failed on the Sequence index until the page was reloaded.
/// </summary>
public sealed class AuditWriter : IAuditWriter
{
    private readonly IAppDbContextFactory _factory;
    private readonly IHashChainService _hasher;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public AuditWriter(IAppDbContextFactory factory, IHashChainService hasher, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _hasher = hasher;
        _user = user;
        _clock = clock;
    }

    public async Task RecordAsync(AuditAction action, string entityType, string? entityId,
        string? caseNumber, string summary, CancellationToken ct = default)
    {
        // REL-05: serialise head-read → append → commit with the interceptor's append path so two
        // concurrent writers can't read the same head and fork the chain.
        await AuditChainGate.EnterAsync(ct);
        try
        {
            using var db = _factory.CreateDbContext();
            var head = await db.AuditLog.AsNoTracking()
                .OrderByDescending(a => a.Sequence).FirstOrDefaultAsync(ct);
            // BUG-219: never earlier than the entry before it, as the interceptor keeps them (BUG-167), so a time range
            // stays a run of consecutive sequence numbers even if the clock steps back.
            var now = _clock.UtcNow;
            if (head is not null && head.AtUtc > now) now = head.AtUtc;

            var entry = new AuditLogEntry
            {
                AtUtc = now,
                Actor = _user.IsAuthenticated ? _user.UserId : "system",
                Action = action,
                EntityType = entityType,
                EntityId = entityId,
                CaseNumber = caseNumber,
                // REV-03: a summary can quote user text (a transfer's details); keep it within the column.
                Summary = summary.Length <= 2000 ? summary : summary[..1999] + "…"
            };
            _hasher.ChainAppend(entry, head);

            db.AuditLog.Add(entry);
            await db.SaveChangesAsync(ct);
        }
        finally
        {
            AuditChainGate.Exit();
        }
    }
}
