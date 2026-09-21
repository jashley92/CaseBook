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
            return;
        }

        try
        {
            using var message = new MailMessage { From = new MailAddress(o.From), Subject = subject };
            foreach (var addr in to) message.To.Add(addr);

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
            await client.SendMailAsync(message, ct);
        }
        catch (Exception ex)
        {
            // As above (CWE-359): the exception is the actionable signal for an SMTP problem; the subject and
            // recipient addresses would only leak personal/case data into the log, so log a count instead.
            _log.LogError(ex, "Failed to send notification email to {RecipientCount} recipient(s).", to.Count);
        }
    }
}
