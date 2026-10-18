namespace IncidentManager.Infrastructure.Notifications;

/// <summary>How the outgoing chat webhook payload is shaped for the target platform.</summary>
public enum ChatWebhookFormat
{
    Slack,
    Teams
}

/// <summary>
/// Outbound team-chat webhook configuration (config section <c>Chat:Webhook</c>, PROD-02). The webhook URL
/// is itself the credential for Slack/Teams incoming webhooks, so — like the SIEM webhook — this lives in
/// server-side configuration (never the in-app editable catalog) and is shown read-only in Admin →
/// Server configuration. CAP-40: when <see cref="WebhookUrl"/> is blank here, an administrator may enter the URL under
/// Settings → Notifications instead (encrypted with Data Protection; this value wins when set). Which notification types
/// are posted here is chosen in-app (<c>Notifications:Chat:*</c>).
/// </summary>
public sealed class ChatOptions
{
    /// <summary>When false (default), no chat is posted and the notifier is a no-op (dev-safe).</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Incoming-webhook URL for the channel (Slack "Incoming Webhooks", or a Teams channel connector/workflow).
    /// It is the secret, so it may be a literal, an <c>@cyberark:</c> reference or a <c>@protected:</c> value resolved at
    /// runtime (F-19, CAP-05). Blank: the URL saved in Administration, if any (CAP-40).
    /// </summary>
    public string WebhookUrl { get; set; } = "";

    /// <summary>Payload shape: Slack (mrkdwn text) or Teams (MessageCard). Default Slack.</summary>
    public ChatWebhookFormat Format { get; set; } = ChatWebhookFormat.Slack;

    /// <summary>Per-POST timeout.</summary>
    public int TimeoutSeconds { get; set; } = 5;

    /// <summary>Delivery attempts per message before it is dropped (>=1).</summary>
    public int MaxAttempts { get; set; } = 3;
}
