using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Notifications;

/// <summary>BUG-101: an alert email that was given up after its retries, as the banner and the case notice show it.</summary>
public sealed record UndeliveredAlert(Guid Id, string Kind, Guid? CaseId, string? CaseNumber, string Subject,
    IReadOnlyList<string> Recipients, DateTimeOffset FirstFailedAtUtc, DateTimeOffset GaveUpAtUtc, int Retries);

/// <summary>
/// BUG-101: the breach-escalation and integrity-alarm emails that never went. Administrators see every one (the banner)
/// and can mark one handled once they've sent it some other way; a breach escalation also shows on its case, to anyone
/// who can see the case, so the team knows Legal may not have heard.
/// </summary>
public sealed class UndeliveredAlertService(IAppDbContextFactory factory, ICurrentUser user, IClock clock)
{
    /// <summary>Every undelivered alert not yet marked handled. Administrators only; empty for anyone else.</summary>
    public async Task<IReadOnlyList<UndeliveredAlert>> ListAsync(CancellationToken ct = default)
    {
        if (!user.Has(Permission.Administer)) return [];
        using var db = factory.CreateDbContext();
        return (await db.AlertDeliveries.AsNoTracking().Where(a => a.GaveUpAtUtc != null && a.DismissedAtUtc == null)
            .ToListAsync(ct)).OrderBy(a => a.FirstFailedAtUtc).Select(View).ToList();
    }

    /// <summary>The undelivered breach escalation for a case the caller can see, if there is one.</summary>
    public async Task<IReadOnlyList<UndeliveredAlert>> ForCaseAsync(Guid caseId, CancellationToken ct = default)
    {
        using var db = factory.CreateDbContext();
        if (!await db.Cases.AsNoTracking().ForUser(user).AnyAsync(c => c.Id == caseId, ct)) return [];
        return (await db.AlertDeliveries.AsNoTracking()
            .Where(a => a.CaseId == caseId && a.GaveUpAtUtc != null && a.DismissedAtUtc == null).ToListAsync(ct))
            .Select(View).ToList();
    }

    /// <summary>Marks an undelivered alert handled (sent by hand, say), which clears its notices.</summary>
    public async Task DismissAsync(Guid id, CancellationToken ct = default)
    {
        if (!user.Has(Permission.Administer)) throw new ForbiddenException(Permission.Administer);
        using var db = factory.CreateDbContext();
        var a = await db.AlertDeliveries.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (a is null || a.DismissedAtUtc is not null) return;
        a.DismissedAtUtc = clock.UtcNow;
        a.DismissedBy = user.UserId;
        await db.SaveChangesAsync(ct);
    }

    private static UndeliveredAlert View(AlertDelivery a) =>
        new(a.Id, a.Kind, a.CaseId, a.CaseNumber, a.Subject, a.RecipientList, a.FirstFailedAtUtc, a.GaveUpAtUtc!.Value, a.Retries);
}
