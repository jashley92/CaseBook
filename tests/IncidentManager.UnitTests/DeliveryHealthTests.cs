using FluentAssertions;
using IncidentManager.Application.Abstractions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// CAP-04: the in-memory record the Diagnostics delivery card reads. Each channel keeps its last good send, its last
/// failure (a safe reason and a code), its back-off, the next try of held work, given-up and dropped counts and its
/// queue; a snapshot is a copy, and a good send ends the back-off it shows.
/// </summary>
public sealed class DeliveryHealthTests
{
    private sealed class Clock : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = new(2026, 10, 18, 9, 0, 0, TimeSpan.Zero);
    }

    [Fact]
    public void A_channel_records_its_sends_failures_and_back_off()
    {
        var clock = new Clock();
        var health = new DeliveryHealth(clock);
        health.Snapshot().Should().BeEmpty("nothing was sent since start");

        health.RecordFailure(DeliveryHealth.Smtp, "SmtpException 535", 535);
        health.RecordBackOff(DeliveryHealth.Smtp, clock.UtcNow.AddMinutes(1));
        var s = health.Snapshot()[DeliveryHealth.Smtp];
        s.LastAttemptFailed.Should().BeTrue();
        s.LastStatusCode.Should().Be(535);
        s.BackedOff(clock.UtcNow).Should().BeTrue();
        s.BackedOff(clock.UtcNow.AddMinutes(2)).Should().BeFalse("the back-off has its end");

        clock.UtcNow = clock.UtcNow.AddMinutes(2);
        health.RecordSuccess(DeliveryHealth.Smtp);
        s = health.Snapshot()[DeliveryHealth.Smtp];
        s.LastAttemptFailed.Should().BeFalse();
        s.BackedOffUntilUtc.Should().BeNull("a good send ends the back-off");
        (s.SuccessCount, s.FailureCount).Should().Be((1, 1));
        s.LastFailure.Should().Be("SmtpException 535", "the last failure stays shown");
    }

    [Fact]
    public void Held_work_given_up_and_queues_are_counted_per_channel()
    {
        var health = new DeliveryHealth(new Clock());
        health.RecordNextAttempt(DeliveryHealth.Smtp, new DateTimeOffset(2026, 10, 18, 9, 5, 0, TimeSpan.Zero));
        health.RecordGivenUp(DeliveryHealth.Smtp);
        health.RecordGivenUp(DeliveryHealth.Smtp);
        health.RecordQueue(DeliveryHealth.Siem("webhook"), dropped: 7, depth: 12);
        health.RecordQueue(DeliveryHealth.Siem("syslog"), dropped: 0, depth: 0);

        var snap = health.Snapshot();
        snap[DeliveryHealth.Smtp].GivenUp.Should().Be(2);
        snap[DeliveryHealth.Smtp].NextAttemptUtc.Should().NotBeNull();
        snap["siem:webhook"].Should().Match<DeliveryChannelStatus>(c => c.Dropped == 7 && c.QueueDepth == 12);
        snap["siem:syslog"].Dropped.Should().Be(0);

        health.RecordNextAttempt(DeliveryHealth.Smtp, null);
        snap[DeliveryHealth.Smtp].NextAttemptUtc.Should().NotBeNull("a snapshot is a copy, not a live view");
        health.Snapshot()[DeliveryHealth.Smtp].NextAttemptUtc.Should().BeNull("nothing waits");
    }

    [Fact]
    public void Concurrent_records_are_all_counted()
    {
        var health = new DeliveryHealth(new Clock());
        Parallel.For(0, 1000, i =>
        {
            if (i % 2 == 0) health.RecordSuccess(DeliveryHealth.Chat);
            else health.RecordFailure(DeliveryHealth.Chat, "HTTP 503", 503);
        });
        var s = health.Snapshot()[DeliveryHealth.Chat];
        (s.SuccessCount + s.FailureCount).Should().Be(1000);
    }
}
