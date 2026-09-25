namespace IncidentManager.Application.Abstractions;

/// <summary>
/// A composed notification message: recipients, subject, an HTML body, and a plain-text alternative for
/// clients that don't render HTML. Built by <see cref="IEmailComposer"/> from a branded template.
/// </summary>
public sealed record EmailMessage(
    IReadOnlyCollection<string> To,
    string Subject,
    string HtmlBody,
    string TextBody);

/// <summary>
/// Sends notification email. Abstracted so the delivery mechanism (real SMTP vs a dev logger) is a
/// configuration concern and the calling code stays testable. Implementations must never throw into
/// the caller — a notification failure must not fail the user action that triggered it.
/// </summary>
public interface IEmailSender
{
    /// <summary>Sends a branded HTML message (with a plain-text alternative). The primary path.</summary>
    Task SendAsync(EmailMessage message, CancellationToken ct = default);

    /// <summary>
    /// Sends a plain-text message. Retained for simple call sites (e.g. the admin "send test" probe);
    /// notification triggers compose branded HTML via <see cref="IEmailComposer"/> and use the overload above.
    /// </summary>
    Task SendAsync(IReadOnlyCollection<string> to, string subject, string body, CancellationToken ct = default);

    /// <summary>
    /// For the admin "send test" buttons only: sends like <see cref="SendAsync(EmailMessage, CancellationToken)"/>
    /// but reports the outcome instead of swallowing a relay failure, so the problem shows where the relay is
    /// being configured. Notification triggers keep using SendAsync.
    /// </summary>
    async Task<EmailSendOutcome> SendTestAsync(EmailMessage message, CancellationToken ct = default)
    {
        await SendAsync(message, ct);
        return new EmailSendOutcome(EmailSendStatus.Sent);
    }
}

public enum EmailSendStatus { Sent, Disabled, Failed }

/// <summary>The result of an admin test send. <see cref="Error"/> carries the relay's reason when it failed.</summary>
public sealed record EmailSendOutcome(EmailSendStatus Status, string? Error = null);
