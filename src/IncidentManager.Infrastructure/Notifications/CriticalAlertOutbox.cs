using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// BUG-101: the breach-escalation and integrity-alarm emails used to be sent once, with a failure only logged. A failed
/// send is now kept in <c>AlertDeliveries</c> and retried by <c>CriticalAlertRetryHostedService</c>; after the last
/// retry it's given up, and administrators (and, for a breach escalation, everyone on the case) see it wasn't delivered.
/// </summary>
public sealed class CriticalAlertOutbox(IEmailSender email, IServiceScopeFactory scopes, IClock clock,
    ILogger<CriticalAlertOutbox> log, IOptionsMonitor<EmailOptions>? emailOptions = null) : ICriticalAlertOutbox, IDisposable
{
    private readonly SemaphoreSlim _retrying = new(1, 1);

    public void Dispose() => _retrying.Dispose();

    /// <summary>The <c>AlertDeliveries.Recipients</c> and <c>.Subject</c> columns.</summary>
    public const int MaxRecipientsLength = 4000, MaxSubjectLength = 1000;

    // The recipients as ';'-joined lists that each fit the column, in order. An address longer than the column on its
    // own can't be any real mailbox (RFC 5321 allows 254) and is left out.
    private static IEnumerable<string> RecipientLists(IEnumerable<string> to)
    {
        var current = new System.Text.StringBuilder();
        foreach (var address in to.Where(a => a.Length <= MaxRecipientsLength))
        {
            if (current.Length > 0 && current.Length + 1 + address.Length > MaxRecipientsLength)
            {
                yield return current.ToString();
                current.Clear();
            }
            if (current.Length > 0) current.Append(';');
            current.Append(address);
        }
        if (current.Length > 0) yield return current.ToString();
    }

    public async Task SendAsync(string kind, Guid? caseId, string? caseNumber, EmailMessage message, CancellationToken ct = default)
    {
        if (message.To.Count == 0) return;
        if (await TrySendAsync(message, ct)) return;
        try
        {
            var now = clock.UtcNow;
            // C12: over their columns the row was refused, so the alert wasn't kept, retried or reported. A recipient list
            // longer than the column is kept as several rows (none dropped); the subject is shortened.
            var subject = TextFit.Cap(message.Subject, MaxSubjectLength);
            DateTimeOffset? next = null;
            // BUG-627: kept without the caller's token. The send failed because the caller gave up (a request ended, the
            // app is shutting down), and the same token then refused the row too: the alarm was neither sent nor kept.
            await using var scope = scopes.CreateAsyncScope();
            await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync(CancellationToken.None);
            foreach (var recipients in RecipientLists(message.To))
            {
                var row = new AlertDelivery
                {
                    Kind = kind, CaseId = caseId, CaseNumber = caseNumber,
                    Recipients = recipients, Subject = subject,
                    HtmlBody = message.HtmlBody, TextBody = message.TextBody, FirstFailedAtUtc = now,
                };
                row.Failed(now);
                next = row.NextAttemptAtUtc;
                db.AlertDeliveries.Add(row);
            }
            await db.SaveChangesAsync(CancellationToken.None);
            log.LogWarning("A {Kind} email wasn't delivered; it will be tried again at {NextAttempt:u}.", kind, next);
        }
        catch (Exception ex)
        {
            log.LogError(ex, "A {Kind} email wasn't delivered and couldn't be queued for another try.", kind);
        }
    }

    public async Task<int> RetryDueAsync(CancellationToken ct = default)
    {
        // WF-92: while email is off the alerts are held, not tried: four failed tries would give them up (and tell everyone
        // Legal may not have heard) within hours, and a given-up alert isn't sent when email is on again.
        if (emailOptions?.CurrentValue.Enabled == false) return 0;
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
                var (delivered, deferred) = await TryRetryAsync(new EmailMessage(a.RecipientList, a.Subject, a.HtmlBody, a.TextBody), ct);
                // BUG-608: the relay is backed off, so nothing was tried: it stays due (next minute's pass) and none of its four
                // retries is spent on a send that never reached the relay.
                if (deferred) continue;
                a.Retries++;
                if (delivered)
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
                // BUG-159: saved after each send, and even while shutting down, so a delivered alert isn't sent to Legal
                // again because a later row's save (or the pass's single save at the end) didn't happen.
                await db.SaveChangesAsync(CancellationToken.None);
            }
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
    private async Task<bool> TrySendAsync(EmailMessage message, CancellationToken ct) => (await TryRetryAsync(message, ct)).Delivered;

    private async Task<(bool Delivered, bool Deferred)> TryRetryAsync(EmailMessage message, CancellationToken ct)
    {
        using var watch = DeliveryWatch.Begin();
        await email.SendAsync(message, ct);
        return (!watch.Failed, watch.Deferred);
    }
}
