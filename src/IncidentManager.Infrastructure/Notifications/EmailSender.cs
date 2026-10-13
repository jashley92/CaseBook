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
public sealed class EmailSender : IEmailSender
{
    private readonly IOptionsMonitor<EmailOptions> _options;
    private readonly ILogger<EmailSender> _log;

    public EmailSender(IOptionsMonitor<EmailOptions> options, ILogger<EmailSender> log)
    {
        _options = options;
        _log = log;
    }

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
            return new EmailSendOutcome(EmailSendStatus.Sent);
        }
        catch (Exception ex) when (ex is SmtpException or InvalidOperationException or FormatException or IOException)
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
        var sent = to.Count(a => MailAddress.TryCreate(a, out _));
        try
        {
            await DeliverAsync(o, to, subject, textBody, htmlBody, ct);
        }
        catch (SmtpFailedRecipientsException ex) when (ex.InnerExceptions.Length < sent)
        {
            // BUG-94: the relay took the message for the other recipients. Sending it again would repeat it to all of
            // them (the executive report went out every hour for a week over one closed mailbox), so it isn't retried.
            _log.LogWarning(ex, "Notification email reached {Delivered} of {RecipientCount} recipient(s); {Failed} address(es) were refused.",
                sent - ex.InnerExceptions.Length, sent, ex.InnerExceptions.Length);
        }
        catch (SmtpFailedRecipientException ex) when (ex is not SmtpFailedRecipientsException && sent > 1)
        {
            // BUG-149: when exactly one of several addresses is refused, SmtpClient throws the singular exception (after
            // the others got the message), so it's the same partial delivery as above.
            _log.LogWarning(ex, "Notification email reached {Delivered} of {RecipientCount} recipient(s); 1 address was refused.",
                sent - 1, sent);
        }
        catch (Exception ex)
        {
            // As above (CWE-359): the exception is the actionable signal for an SMTP problem; the subject and
            // recipient addresses would only leak personal/case data into the log, so log a count instead.
            _log.LogError(ex, "Failed to send notification email to {RecipientCount} recipient(s).", to.Count);
            DeliveryWatch.ReportFailure();   // BUG-08: a scheduled reminder is retried on the next scan
        }
    }

    private async Task DeliverAsync(EmailOptions o, IReadOnlyCollection<string> to, string subject,
        string textBody, string? htmlBody, CancellationToken ct)
    {
        using var message = new MailMessage { From = new MailAddress(o.From), Subject = subject };
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

        // S4423: encrypt the connection by default (Email:EnableSsl, server-side). Only a deliberately
        // configured relay that does its own TLS turns this off.
        using var client = new SmtpClient(o.SmtpHost, o.SmtpPort) { EnableSsl = o.EnableSsl };
        // BUG-99: SmtpClient.Timeout covers only the synchronous Send. A relay that accepts the connection and then stalls
        // would otherwise hold a reminder scan, or a user's assign or reclassify, until the app shut down.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(SendTimeout);
        try
        {
            await client.SendMailAsync(message, timeout.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new SmtpException($"The mail relay didn't finish accepting the message within {SendTimeout.TotalSeconds:0} seconds.");
        }
    }

    internal static TimeSpan SendTimeout { get; set; } = TimeSpan.FromSeconds(30);   // settable for a test
}
