using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// BUG-101: the breach-escalation and integrity-alarm emails used to be sent once, with a failure only logged. A failed
/// send is now kept in <c>AlertDeliveries</c> and retried by <c>CriticalAlertRetryHostedService</c>; after the last
/// retry it's given up, and administrators (and, for a breach escalation, everyone on the case) see it wasn't delivered.
/// </summary>
public sealed class CriticalAlertOutbox(IEmailSender email, IServiceScopeFactory scopes, IClock clock,
    ILogger<CriticalAlertOutbox> log) : ICriticalAlertOutbox
{
    private readonly SemaphoreSlim _retrying = new(1, 1);

    public async Task SendAsync(string kind, Guid? caseId, string? caseNumber, EmailMessage message, CancellationToken ct = default)
    {
        if (message.To.Count == 0) return;
        if (await TrySendAsync(message, ct)) return;
        try
        {
            var now = clock.UtcNow;
            var row = new AlertDelivery
            {
                Kind = kind, CaseId = caseId, CaseNumber = caseNumber,
                Recipients = string.Join(";", message.To), Subject = message.Subject,
                HtmlBody = message.HtmlBody, TextBody = message.TextBody, FirstFailedAtUtc = now,
            };
            row.Failed(now);
            await using var scope = scopes.CreateAsyncScope();
            await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync(ct);
            db.AlertDeliveries.Add(row);
            await db.SaveChangesAsync(ct);
            log.LogWarning("A {Kind} email wasn't delivered; it will be tried again at {NextAttempt:u}.", kind, row.NextAttemptAtUtc);
        }
        catch (Exception ex)
        {
            log.LogError(ex, "A {Kind} email wasn't delivered and couldn't be queued for another try.", kind);
        }
    }

    public async Task<int> RetryDueAsync(CancellationToken ct = default)
    {
        if (!await _retrying.WaitAsync(0, ct)) return 0;
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync(ct);
            var now = clock.UtcNow;
            var due = await db.AlertDeliveries
                .Where(a => a.DeliveredAtUtc == null && a.GaveUpAtUtc == null && a.DismissedAtUtc == null && a.NextAttemptAtUtc <= now)
                .ToListAsync(ct);
            var sent = 0;
            foreach (var a in due)
            {
                a.Retries++;
                if (await TrySendAsync(new EmailMessage(a.RecipientList, a.Subject, a.HtmlBody, a.TextBody), ct))
                {
                    a.DeliveredAtUtc = clock.UtcNow;
                    a.NextAttemptAtUtc = null;
                    sent++;
                    log.LogInformation("A {Kind} email was delivered on retry {Retry}.", a.Kind, a.Retries);
                }
                else
                {
                    a.Failed(clock.UtcNow);
                    if (a.GaveUpAtUtc is not null)
                        log.LogError("A {Kind} email for {CaseNumber} still wasn't delivered after {Retries} retries; administrators are shown it.",
                            a.Kind, a.CaseNumber ?? "(no case)", a.Retries);
                }
            }
            if (due.Count > 0) await db.SaveChangesAsync(ct);
            return sent;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogError(ex, "Retrying undelivered alert emails failed.");
            return 0;
        }
        finally
        {
            _retrying.Release();
        }
    }

    // The sender never throws; a watch says whether this send failed.
    private async Task<bool> TrySendAsync(EmailMessage message, CancellationToken ct)
    {
        using var watch = DeliveryWatch.Begin();
        await email.SendAsync(message, ct);
        return !watch.Failed;
    }
}
