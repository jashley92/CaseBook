namespace IncidentManager.Domain.Entities;

/// <summary>
/// BUG-95: one reminder, digest or report the scheduled scans have sent, so an app restart (an IIS recycle, a
/// deploy) doesn't send it again. The key names what was sent ("overdue|item|due", "digest|user|Daily|2026-10-12");
/// the tracker that owns it builds it. Operational state, deliberately NOT audited or hash-chained (see the
/// interceptor's NotAudited set), like the access log. Marks older than <see cref="Keep"/> are pruned.
/// </summary>
public class NotificationMark
{
    public const int MaxKeyLength = 450;

    /// <summary>How long a mark is kept. A reminder still due after this is sent once more, as a fresh nudge.</summary>
    public static readonly TimeSpan Keep = TimeSpan.FromDays(180);

    public string Key { get; set; } = "";
    public DateTimeOffset SentAtUtc { get; set; }
}
