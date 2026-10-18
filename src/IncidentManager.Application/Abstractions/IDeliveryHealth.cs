namespace IncidentManager.Application.Abstractions;

/// <summary>
/// CAP-04: one outbound channel's delivery, as the senders saw it since the last restart, for the Diagnostics card.
/// Reasons are safe to show: an exception's type and an SMTP or HTTP status, never a recipient, a relay's reply text, a
/// webhook URL or a secret (BUG-657, CWE-359). In-memory ops telemetry: not audited, and reset on restart.
/// </summary>
public sealed record DeliveryChannelStatus(
    string Channel,
    DateTimeOffset? LastSuccessUtc,
    DateTimeOffset? LastFailureUtc,
    string? LastFailure,
    int? LastStatusCode,
    DateTimeOffset? BackedOffUntilUtc,
    DateTimeOffset? NextAttemptUtc,
    long SuccessCount,
    long FailureCount,
    long GivenUp,
    long Dropped,
    int? QueueDepth)
{
    /// <summary>Whether the channel's back-off (BUG-576) still holds sends at <paramref name="now"/>.</summary>
    public bool BackedOff(DateTimeOffset now) => BackedOffUntilUtc is { } until && now < until;

    /// <summary>True when the latest send failed (its failure is newer than its last success).</summary>
    public bool LastAttemptFailed => LastFailureUtc is { } f && (LastSuccessUtc is not { } s || f >= s);

    public static DeliveryChannelStatus Empty(string channel) => new(channel, null, null, null, null, null, null, 0, 0, 0, 0, null);
}

/// <summary>
/// CAP-04: records outbound delivery outcomes app-wide (singleton, in-memory), as <see cref="ISecretResolutionHealth"/>
/// does for CyberArk, so Diagnostics can show whether email, chat and each SIEM transport are getting through. The
/// senders record into it; the card reads <see cref="Snapshot"/>. Always registered, so a sender built without it (a
/// test) just records nothing.
/// </summary>
public interface IDeliveryHealth
{
    /// <summary>When the counts began (the process start, near enough).</summary>
    DateTimeOffset SinceUtc { get; }

    /// <summary>Every channel recorded so far, by name.</summary>
    IReadOnlyDictionary<string, DeliveryChannelStatus> Snapshot();

    void RecordSuccess(string channel);

    /// <summary>A failed send: <paramref name="reason"/> is safe to show (type and status, never a reply's text).</summary>
    void RecordFailure(string channel, string reason, int? statusCode = null);

    /// <summary>The channel's circuit backed it off (BUG-576) until <paramref name="untilUtc"/>.</summary>
    void RecordBackOff(string channel, DateTimeOffset untilUtc);

    /// <summary>When held work is next tried; null when nothing waits.</summary>
    void RecordNextAttempt(string channel, DateTimeOffset? atUtc);

    /// <summary>One message given up after its tries or its age (a held email deleted, BUG-617).</summary>
    void RecordGivenUp(string channel);

    /// <summary>The channel's running count of dropped events and its queue's depth now.</summary>
    void RecordQueue(string channel, long dropped, int depth);
}

/// <inheritdoc />
public sealed class DeliveryHealth(IClock clock) : IDeliveryHealth
{
    /// <summary>The channel names the senders record under.</summary>
    public const string Smtp = "smtp";
    public const string Chat = "chat";
    /// <summary>A SIEM transport's channel: "siem:" and its <c>ISecurityEventTransport.Name</c> (webhook, syslog, eventlog).</summary>
    public static string Siem(string transport) => "siem:" + transport;
    /// <summary>The SIEM stream's shared queue, ahead of the transports' own (SecurityEventQueue).</summary>
    public const string SiemQueue = "siem";

    private readonly object _gate = new();
    private readonly Dictionary<string, DeliveryChannelStatus> _channels = new(StringComparer.Ordinal);

    public DateTimeOffset SinceUtc { get; } = clock.UtcNow;

    public IReadOnlyDictionary<string, DeliveryChannelStatus> Snapshot()
    {
        lock (_gate) return new Dictionary<string, DeliveryChannelStatus>(_channels, StringComparer.Ordinal);
    }

    public void RecordSuccess(string channel) => Update(channel, s => s with
    {
        LastSuccessUtc = clock.UtcNow, SuccessCount = s.SuccessCount + 1, BackedOffUntilUtc = null,
    });

    public void RecordFailure(string channel, string reason, int? statusCode = null) => Update(channel, s => s with
    {
        LastFailureUtc = clock.UtcNow, LastFailure = reason, LastStatusCode = statusCode, FailureCount = s.FailureCount + 1,
    });

    public void RecordBackOff(string channel, DateTimeOffset untilUtc) => Update(channel, s => s with { BackedOffUntilUtc = untilUtc });

    public void RecordNextAttempt(string channel, DateTimeOffset? atUtc) => Update(channel, s => s with { NextAttemptUtc = atUtc });

    public void RecordGivenUp(string channel) => Update(channel, s => s with { GivenUp = s.GivenUp + 1 });

    public void RecordQueue(string channel, long dropped, int depth) => Update(channel, s => s with { Dropped = dropped, QueueDepth = depth });

    private void Update(string channel, Func<DeliveryChannelStatus, DeliveryChannelStatus> change)
    {
        lock (_gate) _channels[channel] = change(_channels.GetValueOrDefault(channel) ?? DeliveryChannelStatus.Empty(channel));
    }
}
