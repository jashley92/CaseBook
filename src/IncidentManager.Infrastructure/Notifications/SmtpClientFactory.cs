using System.Net.Mail;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// BUG-657: the one place an <see cref="SmtpClient"/> is made, so CI's csharpsquid:S5332 waiver covers this file only and
/// the rest of the mail code is still analysed for clear-text connections.
/// </summary>
internal static class SmtpClientFactory
{
    // S4423: encrypt the connection by default (Email:EnableSsl, server-side). Only a deliberately configured relay that
    // does its own TLS turns this off.
    internal static SmtpClient Create(EmailOptions o) => new(o.SmtpHost, o.SmtpPort) { EnableSsl = o.EnableSsl };
}
