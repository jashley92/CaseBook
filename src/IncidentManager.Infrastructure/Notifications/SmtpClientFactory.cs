using System.Net;
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
    // CAP-05: signed in with what SmtpSignIn resolved (none, the username's, or the app-pool account's), and timed by
    // Email:SmtpTimeoutSeconds (Timeout covers the synchronous parts; the send's own token covers the rest, BUG-99).
    internal static SmtpClient Create(EmailOptions o, NetworkCredential? credentials = null, bool integrated = false)
    {
        SmtpClient client = new(o.SmtpHost, o.SmtpPort)   // made here, sent by EmailSender (which gates on the circuit)
        {
            EnableSsl = o.EnableSsl,
            Timeout = (int)SmtpSignIn.Timeout(o).TotalMilliseconds,
        };
        if (integrated) client.UseDefaultCredentials = true;
        else if (credentials is not null) client.Credentials = credentials;
        return client;
    }
}
