using System.Net.Mail;
using System.Net.Mime;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.ApiTokens;
using IncidentManager.Application.Notifications;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// The single notification email path. It reads its options via <see cref="IOptionsMonitor{TOptions}"/>
/// on every send, so administered changes to <c>Email:Enabled</c>, <c>Email:From</c> and the SMTP relay
/// take effect at runtime (A-08) without a restart. When email is disabled the message is logged rather
/// than sent; SMTP failures are logged and swallowed so a mail-server problem never breaks the case
/// operation that triggered the notification; an unwatched one the relay didn't take is held in the database and sent
/// later (BUG-617). Branded messages carry a multipart/alternative body (a
/// plain-text part plus the HTML) so non-HTML clients still get readable text.
/// </summary>
public sealed class EmailSender : IEmailSender, IDisposable
{
    private readonly IOptionsMonitor<EmailOptions> _options;
    private readonly ILogger<EmailSender> _log;
    private readonly OutboundCircuit _circuit;
    private readonly IServiceScopeFactory? _scopes;   // BUG-617: where held mail is kept; without it, none can be

    public EmailSender(IOptionsMonitor<EmailOptions> options, ILogger<EmailSender> log, OutboundCircuit? circuit = null,
        IServiceScopeFactory? scopes = null)
    {
        _options = options;
        _log = log;
        _circuit = circuit ?? new OutboundCircuit();
        _scopes = scopes;
        // BUG-617: mail held before a restart is still in its table, so the first drain looks for it.
        if (scopes is not null)
        {
            _maybeHeld = true;
            ScheduleDrain(DrainFloor);
            // BUG-651: held mail waits while email is off, and goes as soon as it's on again; a corrected relay or From
            // (BUG-652) is tried at once too.
            _onChange = options.OnChange(o =>
            {
                if (o.Enabled) DrainHeldSoon();
            });
        }
    }

    private readonly IDisposable? _onChange;

    // BUG-576: the relay is backed off by host and port, so a corrected relay setting is tried at once.
    internal static string Target(EmailOptions o) => $"smtp:{o.SmtpHost}:{o.SmtpPort}";

    public Task SendAsync(IReadOnlyCollection<string> to, string subject, string body, CancellationToken ct = default) =>
        SendCoreAsync(to, subject, textBody: body, htmlBody: null, ct);

    public Task SendAsync(EmailMessage message, CancellationToken ct = default) =>
        SendCoreAsync(message.To, message.Subject, textBody: message.TextBody, htmlBody: message.HtmlBody, ct);

    public Task SendAsync(EmailMessage message, Guid caseId, IReadOnlyList<string> recipientUserIds, CancellationToken ct = default) =>
        SendCoreAsync(message.To, message.Subject, textBody: message.TextBody, htmlBody: message.HtmlBody, ct,
            new CaseAddressees(caseId, recipientUserIds));

    /// <summary>BUG-654: who a case's email is for, so held mail is checked against the case's audience before it goes.</summary>
    private sealed record CaseAddressees(Guid CaseId, IReadOnlyList<string> UserIds);

    public async Task<EmailSendOutcome> SendTestAsync(EmailMessage message, CancellationToken ct = default)
    {
        if (message.To.Count == 0) return new EmailSendOutcome(EmailSendStatus.Failed, "No recipient.");
        if (!_options.CurrentValue.Enabled)
        {
            await SendCoreAsync(message.To, message.Subject, message.TextBody, message.HtmlBody, ct);
            return new EmailSendOutcome(EmailSendStatus.Disabled);
        }
        try
        {
            await DeliverAsync(_options.CurrentValue, message.To, message.Subject, message.TextBody, message.HtmlBody, ct);
            DrainHeldSoon();   // BUG-608: it answers, so the back-off is over
            return new EmailSendOutcome(EmailSendStatus.Sent);
        }
        // BUG-373: ArgumentException too (an empty sender address, a header MailMessage refuses), so the admin sees the
        // reason instead of an error page.
        catch (Exception ex) when (ex is SmtpException or InvalidOperationException or FormatException or IOException or ArgumentException)
        {
            _log.LogError("Test email to {RecipientCount} recipient(s) failed: {Failure}.", message.To.Count, Failure(ex));   // BUG-657
            // The innermost message names the actual cause (connection refused, auth required, bad address).
            return new EmailSendOutcome(EmailSendStatus.Failed, ex.GetBaseException().Message);
        }
    }

    private async Task SendCoreAsync(IReadOnlyCollection<string> to, string subject,
        string textBody, string? htmlBody, CancellationToken ct, CaseAddressees? about = null)
    {
        if (to.Count == 0) return;

        var o = _options.CurrentValue;
        if (!o.Enabled)
        {
            // Never log the subject or recipient addresses: both carry personal/case data and the app log is a
            // wider-audience sink than the mailbox (CWE-359). The recipient count keeps the operational signal.
            _log.LogInformation("Email delivery disabled; not sending to {RecipientCount} recipient(s).", to.Count);
            // WF-21: not delivered, so not marked sent. A scan's reminders (and the executive report, and critical alerts
            // in their outbox) are held and go out once email is on again, rather than being recorded as sent while off.
            DeliveryWatch.ReportFailure();
            return;
        }

        // REV-47: only the addresses that parse are sent to (BUG-241 skips the rest), so "some got it" is judged against
        // those. Against the whole list, a relay refusing every address it was actually given read as a partial delivery:
        // never retried, no undelivered banner, and a breach email to Legal lost.
        // BUG-576: a relay that just stalled or refused the connection isn't waited on again by every assign, mention and
        // handoff. Not sent, so reported as a failure: a scan retries it and a critical alert goes to its outbox.
        var target = Target(o);
        if (!_circuit.TryEnter(target))
        {
            if (DeliveryWatch.Watching)
            {
                _log.LogWarning("The mail relay isn't answering; not sending to {RecipientCount} recipient(s) until it's tried again.", to.Count);
                DeliveryWatch.ReportDeferred();   // BUG-608: not tried, so an outbox retry isn't spent on it
            }
            else await HoldAsync(to, subject, textBody, htmlBody, attempts: 0, target, about);   // BUG-608: nobody would try it again
            return;
        }

        var outcome = await DeliverLoggedAsync(o, to, subject, textBody, htmlBody, ct);
        // BUG-608: the relay answers again, so what was held while it didn't goes now.
        if (outcome == SendOutcome.Delivered) DrainHeldSoon();
        // BUG-617: nor would anyone try one the relay didn't take, or turned away only for now (BUG-626). A watched send
        // is tried again by its caller, and a refusal would only be refused again.
        else if ((outcome is SendOutcome.NotReached or SendOutcome.Transient or SendOutcome.Blocked) && !DeliveryWatch.Watching)   // BUG-652
            await HoldAsync(to, subject, textBody, htmlBody, attempts: outcome == SendOutcome.Transient ? 1 : 0, target, about);   // BUG-640
    }

    // Delivered when the relay took it (for some recipients at least); a failure is logged and reported to the watch.
    private async Task<SendOutcome> DeliverLoggedAsync(EmailOptions o, IReadOnlyCollection<string> to, string subject,
        string textBody, string? htmlBody, CancellationToken ct)
    {
        var sent = to.Count(a => MailAddress.TryCreate(a, out _));
        try
        {
            await DeliverAsync(o, to, subject, textBody, htmlBody, ct);
            return SendOutcome.Delivered;
        }
        catch (SmtpFailedRecipientsException ex) when (ex.InnerExceptions.Length < sent)
        {
            // BUG-94: the relay took the message for the other recipients. Sending it again would repeat it to all of
            // them (the executive report went out every hour for a week over one closed mailbox), so it isn't retried.
            _log.LogWarning("Notification email reached {Delivered} of {RecipientCount} recipient(s); {Failed} address(es) were refused ({Failure}).",
                sent - ex.InnerExceptions.Length, sent, ex.InnerExceptions.Length, Failure(ex));
            return SendOutcome.Delivered;
        }
        catch (SmtpFailedRecipientException ex) when (ex is not SmtpFailedRecipientsException && sent > 1)
        {
            // BUG-149: when exactly one of several addresses is refused, SmtpClient throws the singular exception (after
            // the others got the message), so it's the same partial delivery as above.
            _log.LogWarning("Notification email reached {Delivered} of {RecipientCount} recipient(s); 1 address was refused ({Failure}).",
                sent - 1, sent, Failure(ex));
            return SendOutcome.Delivered;
        }
        catch (Exception ex)
        {
            // As above (CWE-359): the subject and recipient addresses would only leak personal/case data into the log, so
            // log a count instead; and the exception by its type and SMTP status (BUG-657).
            _log.LogError("Failed to send notification email to {RecipientCount} recipient(s): {Failure}.", to.Count, Failure(ex));
            DeliveryWatch.ReportFailure();   // BUG-08: a scheduled reminder is retried on the next scan
            // BUG-652: no address that parses is this email's own fault, not the settings', so it's final.
            return sent == 0 ? SendOutcome.Refused : SendOutcomes.Of(ex);
        }
    }

    /// <summary>
    /// BUG-657 (CWE-359): a relay's reply often echoes the address it refused ("550 &lt;x@y&gt; no such user"), and the
    /// exception's message carries that reply, so the log gets the exception's type and SMTP status, never its message.
    /// </summary>
    internal static string Failure(Exception ex)
    {
        var text = ex switch
        {
            SmtpFailedRecipientsException many => $"{ex.GetType().Name} {string.Join("/", many.InnerExceptions.Select(r => (int)r.StatusCode).Distinct())}",
            SmtpException s => $"{ex.GetType().Name} {(int)s.StatusCode} {s.StatusCode}",
            _ => ex.GetType().Name,
        };
        var root = ex.GetBaseException();
        if (ReferenceEquals(root, ex) || ex is SmtpFailedRecipientsException) return text;
        return root is System.Net.Sockets.SocketException so ? $"{text}, from {root.GetType().Name} {so.SocketErrorCode}" : $"{text}, from {root.GetType().Name}";
    }

    // BUG-608: an email from a user's action (assign, mention, handoff) that the relay didn't take. Nothing else would try
    // it again (a scan's reminder is retried by the scan, a critical alert by its outbox), and it was dropped with only a
    // log line. It's held, in order, and sent once the relay answers again; past MaxHeld the newest is dropped and logged.
    // BUG-617: held in the HeldEmails table, not in memory, so a restart doesn't lose it; and held too when a send that was
    // tried didn't reach the relay or was turned away for now, not only while the relay is backed off.
    internal const int MaxHeld = 500;

    /// <summary>The least wait before held mail is tried again (settable for a test).</summary>
    internal static TimeSpan DrainFloor { get; set; } = TimeSpan.FromSeconds(15);

    private readonly object _gate = new();   // guards the fields below
    private ITimer? _drainTimer;
    private DateTimeOffset? _drainDue;
    private bool _maybeHeld;          // false only once a drain found the table empty, and nothing was held since
    private long _heldGeneration;     // counts holds, so a drain that found nothing knows whether one came meanwhile
    private int _drainFailures;       // drains in a row that threw (the database unreachable, say), for their back-off
    private int _blockedDrains;       // BUG-652: tries in a row the relay or the settings refused outright, for theirs
    private bool _disposed;
    private int _draining;

    internal async Task<int> HeldCountAsync() => _scopes is null ? 0 : await WithDbAsync(db => db.HeldEmails.CountAsync());

    private async Task HoldAsync(IReadOnlyCollection<string> to, string subject, string textBody, string? htmlBody,
        int attempts, string target, CaseAddressees? about)
    {
        int held;
        try
        {
            // Without the caller's token: a user's action that ended (or a shutdown) mustn't lose the email it was keeping.
            held = _scopes is null ? 0 : await WithDbAsync(async db =>
            {
                var count = await db.HeldEmails.CountAsync(CancellationToken.None);
                if (count >= MaxHeld) return -1;
                db.HeldEmails.Add(new HeldEmail
                {
                    Recipients = string.Join(';', to), Subject = subject, TextBody = textBody, HtmlBody = htmlBody,
                    HeldAtUtc = _circuit.Time.GetUtcNow(), Attempts = attempts,
                    CaseId = about?.CaseId, RecipientUserIds = about is null ? null : string.Join(';', about.UserIds),   // BUG-654
                });
                await db.SaveChangesAsync(CancellationToken.None);
                return count + 1;
            });
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "An email to {RecipientCount} recipient(s) wasn't sent and couldn't be held to send later.", to.Count);
            return;
        }
        // CWE-359 as above: counts, not the subject or addresses.
        if (held == 0)
        {
            _log.LogError("An email to {RecipientCount} recipient(s) wasn't sent, and there's nowhere to hold it.", to.Count);
            return;
        }
        if (held < 0)
        {
            _log.LogError("The mail relay isn't taking mail and {Held} notification emails are already held to send when it does; " +
                "one to {RecipientCount} recipient(s) was dropped.", MaxHeld, to.Count);
            return;
        }
        _log.LogWarning("The mail relay didn't take an email to {RecipientCount} recipient(s); it's held ({Held} in all) " +
            "and sent when the relay takes mail again.", to.Count, held);
        lock (_gate)
        {
            _heldGeneration++;
            _maybeHeld = true;
        }
        ScheduleDrain(_circuit.RetryIn(target));
    }

    private void DrainHeldSoon()
    {
        bool maybe;
        lock (_gate) maybe = _maybeHeld;
        if (maybe) ScheduleDrain(TimeSpan.Zero, floor: false);
    }

    // One timer; a drain due sooner replaces one due later, never the other way round.
    private void ScheduleDrain(TimeSpan delay, bool floor = true)
    {
        if (floor && delay < DrainFloor) delay = DrainFloor;
        var due = _circuit.Time.GetUtcNow() + delay;
        lock (_gate)
        {
            if (_disposed) return;
            if (_drainDue is { } pending && pending <= due) return;
            _drainDue = due;
            _drainTimer ??= CreateDrainTimer();
            _drainTimer.Change(delay, Timeout.InfiniteTimeSpan);
        }
    }

    // Created without the caller's context: a scan's delivery watch mustn't count the held mail's failures as its own.
    private ITimer CreateDrainTimer()
    {
        if (ExecutionContext.IsFlowSuppressed()) return NewDrainTimer();
        using (ExecutionContext.SuppressFlow()) return NewDrainTimer();
    }

    private ITimer NewDrainTimer() =>
        _circuit.Time.CreateTimer(_ => _ = DrainHeldAsync(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);

    /// <summary>Sends the held mail, oldest first, while the relay lets it; one drain at a time.</summary>
    internal async Task DrainHeldAsync()
    {
        lock (_gate) _drainDue = null;
        if (_scopes is null || Interlocked.Exchange(ref _draining, 1) == 1) return;
        var emptied = false;
        try
        {
            while (!emptied)
            {
                long seen;
                lock (_gate) seen = _heldGeneration;
                // BUG-653: the oldest that's due; one put back after a 4xx waits its turn without holding the rest.
                var now = _circuit.Time.GetUtcNow();
                var next = await WithDbAsync(db => db.HeldEmails.AsNoTracking()
                    .Where(h => h.NextAttemptAtUtc == null || h.NextAttemptAtUtc <= now).OrderBy(h => h.Id).FirstOrDefaultAsync());
                lock (_gate) _drainFailures = 0;
                if (next is null
                    && await WithDbAsync(db => db.HeldEmails.MinAsync(h => h.NextAttemptAtUtc)) is { } due)
                {
                    lock (_gate) if (_heldGeneration != seen) continue;   // one held meanwhile is due now
                    ScheduleDrain(due - now);
                    return;
                }
                if (next is null)
                {
                    // Under the lock, so an email held from now on finds no drain running and schedules its own; one held
                    // while the table was read is looked for again.
                    lock (_gate)
                    {
                        if (_heldGeneration != seen) continue;
                        _maybeHeld = false;
                        Volatile.Write(ref _draining, 0);
                        emptied = true;
                    }
                    continue;
                }
                var o = _options.CurrentValue;
                var target = Target(o);
                if (!o.Enabled)
                {
                    // BUG-651: email turned off meanwhile: not sent, as a send made now wouldn't be, and kept, as the outbox
                    // keeps its alerts (WF-92); taken off untried, every held email was lost. They go when email is on
                    // again (OnChange), after the next send that goes, or on this slow look.
                    _log.LogInformation("Email delivery disabled; the held notification emails wait until it's on again.");
                    ScheduleDrain(OutboundCircuit.MaxBackOff);
                    return;
                }
                if (!_circuit.TryEnter(target))
                {
                    ScheduleDrain(_circuit.RetryIn(target));
                    return;
                }
                var outcome = await DeliverHeldAsync(o, target, next);
                if (outcome != SendOutcome.Blocked) lock (_gate) _blockedDrains = 0;
                // BUG-617: it stays first until that's final, so it isn't lost to a relay still down and the order holds.
                // BUG-640: a relay that's down says nothing about the email, so it isn't a try; only age gives it up.
                // BUG-652: nor does a refusal of the session or a setting that stops every send; it's waited out the same way,
                // with its own back-off, as the relay answers and isn't backed off.
                if (outcome is SendOutcome.NotReached or SendOutcome.Blocked)
                {
                    if (_circuit.Time.GetUtcNow() - next.HeldAtUtc < HeldEmail.GiveUpUnreachedAfter)
                    {
                        if (outcome == SendOutcome.Blocked)
                        {
                            int blocked;
                            lock (_gate) blocked = ++_blockedDrains;
                            _log.LogError("The held notification emails can't be sent until the mail relay's sign-in or the email " +
                                "settings are fixed; they're kept and tried again.");
                            ScheduleDrain(BackOff(blocked));
                        }
                        else ScheduleDrain(_circuit.RetryIn(target));
                        return;
                    }
                    if (outcome == SendOutcome.Blocked)
                        _log.LogError("A held email to {RecipientCount} recipient(s) still wasn't sent after {Hours} hours with the mail " +
                            "relay refusing it or the email settings stopping it; it's given up.", next.RecipientList.Count,
                            HeldEmail.GiveUpUnreachedAfter.TotalHours);
                    else
                        _log.LogError("A held email to {RecipientCount} recipient(s) still wasn't sent after {Hours} hours with the mail " +
                            "relay unreachable; it's given up.", next.RecipientList.Count, HeldEmail.GiveUpUnreachedAfter.TotalHours);
                }
                else if (outcome == SendOutcome.Transient)
                {
                    var attempts = next.Attempts + 1;
                    if (attempts < HeldEmail.MaxAttempts)
                    {
                        // BUG-653: that recipient's "not now" is about this email only: it's put back for later, and the
                        // ones behind it go on (strict order is kept only while the relay can't be reached).
                        var id = next.Id;
                        var retryAt = _circuit.Time.GetUtcNow() + BackOff(attempts);
                        await WithDbAsync(db => db.HeldEmails.Where(h => h.Id == id)
                            .ExecuteUpdateAsync(s => s.SetProperty(h => h.Attempts, attempts).SetProperty(h => h.NextAttemptAtUtc, retryAt)));
                        continue;
                    }
                    // One that never goes mustn't hold the rest back for ever.
                    _log.LogError("A held email to {RecipientCount} recipient(s) still wasn't sent after {Attempts} tries; it's given up.",
                        next.RecipientList.Count, attempts);
                }
                else if (outcome == SendOutcome.Refused)
                    _log.LogError("The mail relay refused a held email to {RecipientCount} recipient(s); it isn't tried again.", next.RecipientList.Count);
                var done = next.Id;
                await WithDbAsync(db => db.HeldEmails.Where(h => h.Id == done).ExecuteDeleteAsync());
            }
        }
        catch (Exception ex)
        {
            int failures;
            lock (_gate) failures = ++_drainFailures;
            _log.LogError(ex, "Sending the held notification emails failed; they're tried again shortly.");
            ScheduleDrain(BackOff(failures));
        }
        finally
        {
            if (!emptied) Volatile.Write(ref _draining, 0);
        }
    }

    /// <summary>
    /// Sends a held email. BUG-654: one about a case goes only to those of its recipients who may still see the case, by
    /// the rule its user's action was judged by (<see cref="ReminderAudience.RecipientsAsync"/>): held up to a day, it
    /// reached someone taken off a restricted case or disabled meanwhile. Withdrawn when nobody is left or the case is gone.
    /// </summary>
    private async Task<SendOutcome> DeliverHeldAsync(EmailOptions o, string target, HeldEmail held)
    {
        IReadOnlyCollection<string> to = held.RecipientList;
        if (held.CaseId is { } caseId)
        {
            List<string>? kept;
            try { kept = await StillEntitledAsync(caseId, held.RecipientList, held.RecipientUserIdList); }
            catch
            {
                _circuit.Release(target);   // nothing was sent (BUG-607)
                throw;
            }
            if (kept is null || kept.Count == 0)
            {
                _circuit.Release(target);
                if (kept is null)
                    _log.LogInformation("A held email about a case that no longer exists wasn't sent ({RecipientCount} recipient(s)).",
                        held.RecipientList.Count);
                else
                    _log.LogInformation("A held email wasn't sent: none of its {RecipientCount} recipient(s) may still see the case.",
                        held.RecipientList.Count);
                return SendOutcome.Withdrawn;
            }
            if (kept.Count < held.RecipientList.Count)
                _log.LogInformation("A held email goes to {Kept} of its {RecipientCount} recipient(s); the others may no longer see the case.",
                    kept.Count, held.RecipientList.Count);
            to = kept;
        }
        return await DeliverLoggedAsync(o, to, held.Subject, held.TextBody, held.HtmlBody, CancellationToken.None);
    }

    // BUG-654: the addresses (paired in order with their users) whose users may still see the case; null when it's gone.
    private async Task<List<string>?> StillEntitledAsync(Guid caseId, IReadOnlyList<string> addresses, IReadOnlyList<string> userIds)
    {
        var scopes = _scopes ?? throw new InvalidOperationException("No database to hold email in.");
        await using var scope = scopes.CreateAsyncScope();
        var sp = scope.ServiceProvider;
        await using var db = await sp.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync(CancellationToken.None);
        var c = await db.Cases.AsNoTracking().Where(x => x.Id == caseId)
            .Select(x => new { x.IsRestricted, x.IncidentCommander, Team = x.Assignments.Select(a => a.UserId).ToList() })
            .FirstOrDefaultAsync(CancellationToken.None);
        if (c is null) return null;
        var audience = sp.GetService<ReminderAudience>()
            ?? new ReminderAudience(sp.GetService<IUserDirectory>(), sp.GetService<IRoleDirectory>(), sp.GetService<ITokenOwnerCheck>());
        var entitled = (await audience.RecipientsAsync(userIds, c.IsRestricted, c.IncidentCommander, c.Team, CancellationToken.None))
            .ToHashSet(StringComparer.Ordinal);
        // An address with no user beside it (a list stored short) isn't sent to: who it's for can't be checked.
        return addresses.Where((_, i) => i < userIds.Count && entitled.Contains(userIds[i])).ToList();
    }

    // The wait after the n-th try in a row that didn't go: DrainFloor, doubling, up to the circuit's longest back-off.
    private static TimeSpan BackOff(int tries) =>
        TimeSpan.FromTicks(Math.Min(DrainFloor.Ticks << Math.Clamp(tries - 1, 0, 16), OutboundCircuit.MaxBackOff.Ticks));

    private async Task<T> WithDbAsync<T>(Func<AppDbContext, Task<T>> work)
    {
        var scopes = _scopes ?? throw new InvalidOperationException("No database to hold email in.");
        await using var scope = scopes.CreateAsyncScope();
        await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>()
            .CreateDbContextAsync(CancellationToken.None);
        return await work(db);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            _drainTimer?.Dispose();
        }
        _onChange?.Dispose();
    }

    private async Task DeliverAsync(EmailOptions o, IReadOnlyCollection<string> to, string subject,
        string textBody, string? htmlBody, CancellationToken ct)
    {
        var target = Target(o);
        using var message = NotYetSent(target, () => Compose(o, to, subject, textBody, htmlBody));

        using var client = NotYetSent(target, () => SmtpClientFactory.Create(o));   // BUG-657: TLS per Email:EnableSsl (S4423)
        // BUG-99: SmtpClient.Timeout covers only the synchronous Send. A relay that accepts the connection and then stalls
        // would otherwise hold a reminder scan, or a user's assign or reclassify, until the app shut down.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(SendTimeout);
        try
        {
            await client.SendMailAsync(message, timeout.Token);
            _circuit.Succeeded(target);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            _circuit.Failed(target);   // BUG-576
            throw new SmtpException($"The mail relay didn't finish accepting the message within {SendTimeout.TotalSeconds:0} seconds.");
        }
        catch (OperationCanceledException)
        {
            _circuit.Release(target);   // BUG-607: the caller gave up, which says nothing about the relay
            throw;
        }
        catch (Exception ex) when (Unreachable(ex))
        {
            _circuit.Failed(target);   // BUG-576: couldn't reach it, or it dropped the session
            throw;
        }
        catch
        {
            // BUG-607: it answered (refused an address, wanted authentication, a mailbox busy), so it isn't backed off.
            // Reported as neither, a probe's turn was held and every send failed fast for ten minutes.
            _circuit.Succeeded(target);
            throw;
        }
    }

    // BUG-607: a send that fails before anything reaches the relay (no valid address, a bad From or port) hands back the
    // probe's turn it may hold.
    private T NotYetSent<T>(string target, Func<T> make)
    {
        try { return make(); }
        catch
        {
            _circuit.Release(target);
            throw;
        }
    }

    // A MailMessage for the addresses that parse. Throws (and disposes it) when there's nothing to send to or no valid From.
    private MailMessage Compose(EmailOptions o, IReadOnlyCollection<string> to, string subject, string textBody, string? htmlBody)
    {
        var message = new MailMessage();
        try
        {
            // BUG-373: a subject stored with a line break (an alert queued before the composer collapsed them) is sent on
            // retry instead of throwing again.
            message.From = new MailAddress(o.From);
            message.Subject = EmailComposer.SingleLine(subject);
            AddRecipientsAndBody(message, to, textBody, htmlBody);
            return message;
        }
        catch
        {
            message.Dispose();
            throw;
        }
    }

    private void AddRecipientsAndBody(MailMessage message, IReadOnlyCollection<string> to, string textBody, string? htmlBody)
    {
        // BUG-241: one bad address (a typo in a list set in the file) mustn't stop the message reaching the rest.
        var bad = 0;
        foreach (var addr in to)
        {
            if (MailAddress.TryCreate(addr, out var parsed)) message.To.Add(parsed);
            else bad++;
        }
        if (bad > 0)
        {
            if (message.To.Count == 0) throw new FormatException($"None of the {to.Count} recipient address(es) is a valid email address.");
            _log.LogWarning("Skipped {Bad} recipient address(es) that aren't valid email addresses; sending to {Good}.", bad, message.To.Count);
        }

        if (htmlBody is null)
        {
            message.Body = textBody;
        }
        else
        {
            // multipart/alternative: text first (fallback), HTML preferred by capable clients.
            message.Body = textBody;
            message.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(
                htmlBody, null, MediaTypeNames.Text.Html));
        }
    }

    // A relay that answered with a refusal (auth required, sender refused) isn't hung, so it isn't backed off.
    // BUG-650: refused addresses are an answer too, though SmtpClient gives several of them GeneralFailure.
    internal static bool Unreachable(Exception ex) => ex switch
    {
        SmtpFailedRecipientException => false,
        SmtpException s => s.StatusCode is SmtpStatusCode.GeneralFailure or SmtpStatusCode.ServiceNotAvailable
            || s.InnerException is IOException or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException,
        _ => ex is IOException or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException,
    };

    internal static TimeSpan SendTimeout { get; set; } = TimeSpan.FromSeconds(30);   // settable for a test
}
