using System.Net.Mail;
using System.Net.Mime;
using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// The single notification email path. It reads its options via <see cref="IOptionsMonitor{TOptions}"/>
/// on every send, so administered changes to <c>Email:Enabled</c>, <c>Email:From</c> and the SMTP relay
/// take effect at runtime (A-08) without a restart. When email is disabled the message is logged rather
/// than sent; SMTP failures are logged and swallowed so a mail-server problem never breaks the case
/// operation that triggered the notification. Branded messages carry a multipart/alternative body (a
/// plain-text part plus the HTML) so non-HTML clients still get readable text.
/// </summary>
public sealed class EmailSender : IEmailSender, IDisposable
{
    private readonly IOptionsMonitor<EmailOptions> _options;
    private readonly ILogger<EmailSender> _log;
    private readonly OutboundCircuit _circuit;

    public EmailSender(IOptionsMonitor<EmailOptions> options, ILogger<EmailSender> log, OutboundCircuit? circuit = null)
    {
        _options = options;
        _log = log;
        _circuit = circuit ?? new OutboundCircuit();
    }

    // BUG-576: the relay is backed off by host and port, so a corrected relay setting is tried at once.
    internal static string Target(EmailOptions o) => $"smtp:{o.SmtpHost}:{o.SmtpPort}";

    public Task SendAsync(IReadOnlyCollection<string> to, string subject, string body, CancellationToken ct = default) =>
        SendCoreAsync(to, subject, textBody: body, htmlBody: null, ct);

    public Task SendAsync(EmailMessage message, CancellationToken ct = default) =>
        SendCoreAsync(message.To, message.Subject, textBody: message.TextBody, htmlBody: message.HtmlBody, ct);

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
            _log.LogError(ex, "Test email to {RecipientCount} recipient(s) failed.", message.To.Count);
            // The innermost message names the actual cause (connection refused, auth required, bad address).
            return new EmailSendOutcome(EmailSendStatus.Failed, ex.GetBaseException().Message);
        }
    }

    private async Task SendCoreAsync(IReadOnlyCollection<string> to, string subject,
        string textBody, string? htmlBody, CancellationToken ct)
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
            else Hold(new HeldEmail([.. to], subject, textBody, htmlBody), target);   // BUG-608: nobody would try it again
            return;
        }

        // BUG-608: the relay answers again, so what was held while it didn't goes now.
        if (await DeliverLoggedAsync(o, to, subject, textBody, htmlBody, ct)) DrainHeldSoon();
    }

    // True when the relay took it (for some recipients at least); a failure is logged and reported to the watch.
    private async Task<bool> DeliverLoggedAsync(EmailOptions o, IReadOnlyCollection<string> to, string subject,
        string textBody, string? htmlBody, CancellationToken ct)
    {
        var sent = to.Count(a => MailAddress.TryCreate(a, out _));
        try
        {
            await DeliverAsync(o, to, subject, textBody, htmlBody, ct);
            return true;
        }
        catch (SmtpFailedRecipientsException ex) when (ex.InnerExceptions.Length < sent)
        {
            // BUG-94: the relay took the message for the other recipients. Sending it again would repeat it to all of
            // them (the executive report went out every hour for a week over one closed mailbox), so it isn't retried.
            _log.LogWarning(ex, "Notification email reached {Delivered} of {RecipientCount} recipient(s); {Failed} address(es) were refused.",
                sent - ex.InnerExceptions.Length, sent, ex.InnerExceptions.Length);
            return true;
        }
        catch (SmtpFailedRecipientException ex) when (ex is not SmtpFailedRecipientsException && sent > 1)
        {
            // BUG-149: when exactly one of several addresses is refused, SmtpClient throws the singular exception (after
            // the others got the message), so it's the same partial delivery as above.
            _log.LogWarning(ex, "Notification email reached {Delivered} of {RecipientCount} recipient(s); 1 address was refused.",
                sent - 1, sent);
            return true;
        }
        catch (Exception ex)
        {
            // As above (CWE-359): the exception is the actionable signal for an SMTP problem; the subject and
            // recipient addresses would only leak personal/case data into the log, so log a count instead.
            _log.LogError(ex, "Failed to send notification email to {RecipientCount} recipient(s).", to.Count);
            DeliveryWatch.ReportFailure();   // BUG-08: a scheduled reminder is retried on the next scan
            return false;
        }
    }

    // BUG-608: an email from a user's action (assign, mention, handoff) that came while the relay was backed off. Nothing
    // else would try it again (a scan's reminder is retried by the scan, a critical alert by its outbox), and the back-off
    // dropped it with only a log line. It's held here, in memory and in order, and sent once the relay answers again;
    // past MaxHeld the newest is dropped and logged. Lost if the app restarts meanwhile.
    private sealed record HeldEmail(IReadOnlyCollection<string> To, string Subject, string TextBody, string? HtmlBody);

    internal const int MaxHeld = 500;

    /// <summary>The least wait before held mail is tried again (settable for a test).</summary>
    internal static TimeSpan DrainFloor { get; set; } = TimeSpan.FromSeconds(15);

    private readonly Queue<HeldEmail> _held = new();   // under its own lock, as are _drainTimer and _drainDue
    private ITimer? _drainTimer;
    private DateTimeOffset? _drainDue;
    private int _draining;

    internal int HeldCount { get { lock (_held) return _held.Count; } }

    private void Hold(HeldEmail email, string target)
    {
        int held;
        lock (_held)
        {
            held = _held.Count < MaxHeld ? _held.Count + 1 : -1;
            if (held > 0) _held.Enqueue(email);
        }
        // CWE-359 as above: counts, not the subject or addresses.
        if (held < 0)
            _log.LogError("The mail relay isn't answering and {Held} notification emails are already held to send when it does; " +
                "one to {RecipientCount} recipient(s) was dropped.", MaxHeld, email.To.Count);
        else
            _log.LogWarning("The mail relay isn't answering; an email to {RecipientCount} recipient(s) is held ({Held} in all) " +
                "and sent when it answers again.", email.To.Count, held);
        ScheduleDrain(_circuit.RetryIn(target));
    }

    private void DrainHeldSoon()
    {
        if (HeldCount > 0) ScheduleDrain(TimeSpan.Zero, floor: false);
    }

    // One timer; a drain due sooner replaces one due later, never the other way round.
    private void ScheduleDrain(TimeSpan delay, bool floor = true)
    {
        if (floor && delay < DrainFloor) delay = DrainFloor;
        var due = _circuit.Time.GetUtcNow() + delay;
        lock (_held)
        {
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
        lock (_held) _drainDue = null;
        if (Interlocked.Exchange(ref _draining, 1) == 1) return;
        var emptied = false;
        try
        {
            while (true)
            {
                HeldEmail next;
                lock (_held)
                {
                    if (!_held.TryPeek(out var first))
                    {
                        // Under the lock, so an email held from now on finds no drain running and schedules its own.
                        Volatile.Write(ref _draining, 0);
                        emptied = true;
                        return;
                    }
                    next = first;
                }
                var o = _options.CurrentValue;
                var target = Target(o);
                if (o.Enabled && !_circuit.TryEnter(target))
                {
                    ScheduleDrain(_circuit.RetryIn(target));
                    return;
                }
                lock (_held) _held.Dequeue();
                // Email turned off meanwhile: not sent, as a send made now wouldn't be.
                if (!o.Enabled) _log.LogInformation("Email delivery disabled; not sending a held email to {RecipientCount} recipient(s).", next.To.Count);
                else await DeliverLoggedAsync(o, next.To, next.Subject, next.TextBody, next.HtmlBody, CancellationToken.None);
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Sending the held notification emails failed; they're tried again shortly.");
            ScheduleDrain(DrainFloor);
        }
        finally
        {
            if (!emptied) Volatile.Write(ref _draining, 0);
        }
    }

    public void Dispose()
    {
        lock (_held) _drainTimer?.Dispose();
    }

    private async Task DeliverAsync(EmailOptions o, IReadOnlyCollection<string> to, string subject,
        string textBody, string? htmlBody, CancellationToken ct)
    {
        var target = Target(o);
        using var message = NotYetSent(target, () => Compose(o, to, subject, textBody, htmlBody));

        // S4423: encrypt the connection by default (Email:EnableSsl, server-side). Only a deliberately
        // configured relay that does its own TLS turns this off.
        using var client = NotYetSent(target, () => new SmtpClient(o.SmtpHost, o.SmtpPort) { EnableSsl = o.EnableSsl });
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
    private static bool Unreachable(Exception ex) => ex switch
    {
        SmtpException s => s.StatusCode is SmtpStatusCode.GeneralFailure or SmtpStatusCode.ServiceNotAvailable
            || s.InnerException is IOException or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException,
        _ => ex is IOException or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException,
    };

    internal static TimeSpan SendTimeout { get; set; } = TimeSpan.FromSeconds(30);   // settable for a test
}
