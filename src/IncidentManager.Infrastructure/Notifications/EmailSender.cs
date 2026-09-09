using System.Net.Mail;
using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// The single notification email path. It reads its options via <see cref="IOptionsMonitor{TOptions}"/>
/// on every send, so administered changes to <c>Email:Enabled</c>, <c>Email:From</c> and the SMTP relay
/// take effect at runtime (A-08) without a restart. When email is disabled the message is logged rather
/// than sent; SMTP failures are logged and swallowed so a mail-server problem never breaks the case
/// operation that triggered the notification.
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

    public async Task SendAsync(IReadOnlyCollection<string> to, string subject, string body, CancellationToken ct = default)
    {
        if (to.Count == 0) return;

        var o = _options.CurrentValue;
        if (!o.Enabled)
        {
            _log.LogInformation("Email delivery disabled; not sending '{Subject}' to {To}", subject, string.Join(", ", to));
            return;
        }

        try
        {
            using var message = new MailMessage { From = new MailAddress(o.From), Subject = subject, Body = body };
            foreach (var addr in to) message.To.Add(addr);

            using var client = new SmtpClient(o.SmtpHost, o.SmtpPort);
            await client.SendMailAsync(message, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to send notification email '{Subject}' to {To}", subject, string.Join(", ", to));
        }
    }
}
