namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Sends notification email. Abstracted so the delivery mechanism (real SMTP vs a dev logger) is a
/// configuration concern and the calling code stays testable. Implementations must never throw into
/// the caller — a notification failure must not fail the user action that triggered it.
/// </summary>
public interface IEmailSender
{
    Task SendAsync(IReadOnlyCollection<string> to, string subject, string body, CancellationToken ct = default);
}
