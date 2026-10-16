using System.Net.Mail;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// C20 (BUG-617, BUG-626): what became of one send, so queued mail is removed only when that's final. Delivered
/// (to some recipients at least, BUG-94) and Refused (the relay said no for good) end it; NotReached (the relay didn't
/// answer, or the send was cut off) and Transient (a 4xx: mailbox busy, local error, out of storage) keep it to try again.
/// </summary>
internal enum SendOutcome
{
    Delivered,
    NotReached,
    Transient,
    Refused,
}

internal static class SendOutcomes
{
    /// <summary>The outcome of a send that threw <paramref name="ex"/> (a partial delivery is decided before this).</summary>
    public static SendOutcome Of(Exception ex) => ex switch
    {
        OperationCanceledException => SendOutcome.NotReached,
        _ when EmailSender.Unreachable(ex) => SendOutcome.NotReached,
        // BUG-626: 450/451/452 (and any other 4xx) say "not now", not "never": the same mail may go on a later try. When
        // several addresses were refused, one refused only for now is worth the retry (the rest were refused, not sent).
        SmtpFailedRecipientsException many => many.InnerExceptions.Any(r => IsTransient(r.StatusCode)) ? SendOutcome.Transient : SendOutcome.Refused,
        SmtpException s when IsTransient(s.StatusCode) => SendOutcome.Transient,
        _ => SendOutcome.Refused,
    };

    private static bool IsTransient(SmtpStatusCode code) => (int)code is >= 400 and < 500;
}
