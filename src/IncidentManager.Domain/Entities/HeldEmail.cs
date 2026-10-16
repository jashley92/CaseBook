namespace IncidentManager.Domain.Entities;

/// <summary>
/// BUG-617: an email from a user's action (assign, mention, handoff) that the relay didn't take, kept to send when it
/// answers. Nothing else tries these again (a scan retries its reminders, a critical alert has its outbox), and held in
/// memory they were lost on a restart. A row is removed once it's sent, refused for good, given up after
/// <see cref="MaxAttempts"/> temporary refusals, or given up when the relay still can't be reached
/// <see cref="GiveUpUnreachedAfter"/> after it was held. Operational state, deliberately NOT audited or hash-chained (see
/// the interceptor's NotAudited set), like <see cref="AlertDelivery"/>: the drain updates and deletes it, and it isn't
/// case data.
/// </summary>
public class HeldEmail
{
    /// <summary>
    /// Tries the relay answered with a temporary refusal (a 4xx: mailbox busy, out of storage) before it's given up.
    /// BUG-640: a try that didn't reach the relay isn't counted, or a relay down for over an hour dropped held mail.
    /// </summary>
    public const int MaxAttempts = 12;

    /// <summary>BUG-640: how long a held email is kept while the relay can't be reached at all.</summary>
    public static readonly TimeSpan GiveUpUnreachedAfter = TimeSpan.FromHours(24);

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
