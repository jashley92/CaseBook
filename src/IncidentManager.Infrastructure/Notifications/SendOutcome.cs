using System.Net.Mail;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// C20 (BUG-617, BUG-626): what became of one send, so queued mail is removed only when that's final. Delivered
/// (to some recipients at least, BUG-94) and Refused (the relay said no for good) end it; NotReached (the relay didn't
/// answer, or the send was cut off) and Transient (a 4xx: mailbox busy, local error, out of storage) keep it to try again.
/// Blocked (BUG-652: the relay refused the session, or the settings stop every send) keeps it too, like NotReached;
/// the drain puts a Blocked email back on its own, and reads it as the session's only when the next is Blocked too (BUG-659).
/// </summary>
internal enum SendOutcome
{
    Delivered,
    NotReached,
    Transient,
    Refused,
    Blocked,
    /// <summary>BUG-654: a held email nobody it was for may still receive (the case is gone, or they lost access): not sent.</summary>
    Withdrawn,
    /// <summary>
    /// CAP-05: the relay refused the sign-in (530, 534, 535, 538), or one it refused isn't tried again yet. Kept, as
    /// Blocked is, but certain to be the settings' and not one email's, so the drain doesn't try the next to find out
    /// (BUG-659): each try with a wrong password counts towards locking the account out.
    /// </summary>
    SignInRefused,
}

internal static class SendOutcomes
{
    /// <summary>The outcome of a send that threw <paramref name="ex"/> (a partial delivery is decided before this).</summary>
    public static SendOutcome Of(Exception ex) => ex switch
    {
        OperationCanceledException => SendOutcome.NotReached,
        // CAP-05: first, as some relays refuse an unsigned session at RCPT (530 5.7.1), which would otherwise read as
        // the addresses refused for good and delete the email.
        _ when EmailSender.SignInRefused(ex) => SendOutcome.SignInRefused,
        _ when EmailSender.Unreachable(ex) => SendOutcome.NotReached,
        // BUG-626: 450/451/452 (and any other 4xx) say "not now", not "never": the same mail may go on a later try. When
        // several addresses were refused, one refused only for now is worth the retry (the rest were refused, not sent).
        SmtpFailedRecipientsException many => many.InnerExceptions.Any(r => IsTransient(r.StatusCode)) ? SendOutcome.Transient : SendOutcome.Refused,
        SmtpException s when IsTransient(s.StatusCode) => SendOutcome.Transient,
        // BUG-652: only the addresses' own refusal is final for the email. A 5xx to the session (530 authentication, 553
        // the sender) or our own setting (a From that doesn't parse) refuses every email alike, and read as Refused a
        // drain deleted the whole held queue in seconds.
        SmtpFailedRecipientException => SendOutcome.Refused,
        // BUG-659: 552 (too large) is about this message only, at whatever step. 550 and 554 may be the session's (the
        // sender, the greeting), so they stay Blocked, and the drain tells one email's refusal from the session's.
        SmtpException { StatusCode: SmtpStatusCode.ExceededStorageAllocation } => SendOutcome.Refused,
        _ => SendOutcome.Blocked,
    };

    private static bool IsTransient(SmtpStatusCode code) => (int)code is >= 400 and < 500;
}
