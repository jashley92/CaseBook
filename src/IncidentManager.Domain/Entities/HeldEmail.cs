namespace IncidentManager.Domain.Entities;

/// <summary>
/// BUG-617: an email from a user's action (assign, mention, handoff) that the relay didn't take, kept to send when it
/// answers. Nothing else tries these again (a scan retries its reminders, a critical alert has its outbox), and held in
/// memory they were lost on a restart. A row is removed once it's sent, refused for good, or given up after
/// <see cref="MaxAttempts"/> tries. Operational state, deliberately NOT audited or hash-chained (see the interceptor's
/// NotAudited set), like <see cref="AlertDelivery"/>: the drain updates and deletes it, and it isn't case data.
/// </summary>
public class HeldEmail
{
    /// <summary>Tries (sends that reached the point of talking to the relay) before it's given up.</summary>
    public const int MaxAttempts = 12;

    /// <summary>Assigned by the database, in the order the emails were held: the drain sends the oldest first.</summary>
    public long Id { get; set; }

    /// <summary>The recipients, separated by ';'.</summary>
    public string Recipients { get; set; } = "";
    public string Subject { get; set; } = "";
    public string TextBody { get; set; } = "";
    public string? HtmlBody { get; set; }

    public DateTimeOffset HeldAtUtc { get; set; }
    public int Attempts { get; set; }

    public IReadOnlyList<string> RecipientList => Recipients.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
