namespace IncidentManager.Domain.Entities;

/// <summary>
/// BUG-101: a breach-escalation or integrity-alarm (audit chain, evidence drift) email whose send failed, kept so it's tried again and, if it never
/// goes, so people see that it didn't. A row exists only for a failed send. Operational state, deliberately NOT
/// audited or hash-chained (see the interceptor's NotAudited set): retries update it, and the alarm itself is already
/// carried by the critical log line and the SIEM event.
/// </summary>
public class AlertDelivery
{
    public const string BreachEscalation = "BreachEscalation";
    public const string IntegrityAlarm = "IntegrityAlarm";
    public const string EvidenceDriftAlarm = "EvidenceDriftAlarm";   // BUG-158

    /// <summary>How long after the first failure each retry waits. After the last, the send is given up.</summary>
    public static readonly TimeSpan[] RetryAfter =
        [TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30), TimeSpan.FromHours(2)];

    public Guid Id { get; set; } = Guid.NewGuid();
    public string Kind { get; set; } = "";
    public Guid? CaseId { get; set; }
    public string? CaseNumber { get; set; }

    /// <summary>The recipients, separated by ';'.</summary>
    public string Recipients { get; set; } = "";
    public string Subject { get; set; } = "";
    public string HtmlBody { get; set; } = "";
    public string TextBody { get; set; } = "";

    public DateTimeOffset FirstFailedAtUtc { get; set; }
    /// <summary>Retries made so far (the first send isn't counted).</summary>
    public int Retries { get; set; }
    public DateTimeOffset? NextAttemptAtUtc { get; set; }
    public DateTimeOffset? DeliveredAtUtc { get; set; }
    public DateTimeOffset? GaveUpAtUtc { get; set; }

    /// <summary>An administrator confirmed it was handled (sent by hand, say), which clears the notices.</summary>
    public DateTimeOffset? DismissedAtUtc { get; set; }
    public string? DismissedBy { get; set; }

    public IReadOnlyList<string> RecipientList => Recipients.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>Records a failed retry: schedules the next, or gives up after the last.</summary>
    public void Failed(DateTimeOffset nowUtc)
    {
        if (Retries < RetryAfter.Length)
        {
            // BUG-291: and never sooner than the usual gap after this try. Timed from the first failure alone, an alert held
            // while email was off (WF-92) had every retry overdue when it came back: one a minute, and given up in minutes.
            var gap = RetryAfter[Retries] - (Retries == 0 ? TimeSpan.Zero : RetryAfter[Retries - 1]);
            var scheduled = FirstFailedAtUtc + RetryAfter[Retries];
            NextAttemptAtUtc = scheduled > nowUtc + gap ? scheduled : nowUtc + gap;
        }
        else
        {
            NextAttemptAtUtc = null;
            GaveUpAtUtc = nowUtc;
        }
    }
}
