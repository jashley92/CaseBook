namespace IncidentManager.Application.Abstractions;

/// <summary>Relative urgency of a chat notification; used only to tint the message (e.g. a Teams themeColor).</summary>
public enum ChatUrgency
{
    Normal,
    Alert
}

/// <summary>
/// A concise chat notification for a shared SOC channel: a short title, a line or two of text, and an
/// optional deep link back into CaseBook. The transport renders it per platform (Slack mrkdwn / Teams card).
/// </summary>
public sealed record ChatNotification(string Title, string Text, string? Url = null, ChatUrgency Urgency = ChatUrgency.Normal);

/// <summary>
/// Posts case-lifecycle notifications to a shared team chat (Slack/Teams incoming webhook) — a broadcast
/// channel alongside the per-recipient email path (PROD-02). Abstracted so the delivery mechanism is a
/// configuration concern; implementations are best-effort and must never throw into the caller.
/// </summary>
public interface IChatNotifier
{
    /// <summary>Whether a chat webhook is configured to deliver right now (read live from options).</summary>
    bool Enabled { get; }

    /// <summary>Posts one message to the configured channel. A no-op (not an error) when disabled.</summary>
    Task SendAsync(ChatNotification message, CancellationToken ct = default);
}
