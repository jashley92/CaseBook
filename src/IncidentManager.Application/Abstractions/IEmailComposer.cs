namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Renders a notification into a branded HTML <see cref="EmailMessage"/> (E-03b): resolves the effective
/// template (admin override or catalog default), substitutes tokens (scalar values HTML-encoded so case
/// text can't inject markup; list tokens are app-rendered safe HTML), inlines styles for email clients, and
/// wraps the content in the shared branded shell (logo, console colours, header/footer, optional CTA button).
/// </summary>
public interface IEmailComposer
{
    /// <summary>
    /// Composes a message for <paramref name="templateId"/>. <paramref name="tokens"/> are scalar values
    /// (HTML-encoded on substitution); <paramref name="htmlTokens"/> are app-rendered safe HTML fragments
    /// (e.g. an item list); <paramref name="ctaUrl"/>, when non-empty, renders the template's CTA button.
    /// </summary>
    Task<EmailMessage> ComposeAsync(
        string templateId,
        IReadOnlyCollection<string> to,
        IReadOnlyDictionary<string, string> tokens,
        string? ctaUrl = null,
        IReadOnlyDictionary<string, string>? htmlTokens = null,
        CancellationToken ct = default);

    /// <summary>
    /// Renders a preview from a (possibly unsaved) subject + body using representative sample token values,
    /// for the admin editor. Returns the email subject and the full branded HTML document.
    /// </summary>
    Task<(string Subject, string Html)> PreviewAsync(
        string templateId, string subject, string bodyHtml, CancellationToken ct = default);

    /// <summary>
    /// Composes a full message for the currently-saved template using representative sample token values —
    /// for the admin "send test" action, so an admin can see a real rendered email in their inbox.
    /// </summary>
    Task<EmailMessage> ComposeSampleAsync(string templateId, IReadOnlyCollection<string> to, CancellationToken ct = default);
}
