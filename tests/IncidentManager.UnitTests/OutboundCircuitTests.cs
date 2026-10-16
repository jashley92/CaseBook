using FluentAssertions;
using IncidentManager.Infrastructure.Notifications;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>BUG-576: a target that isn't answering is backed off (1 min, doubling to 10 min) and failed fast meanwhile.</summary>
public sealed class OutboundCircuitTests
{
    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 16, 9, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public void A_target_that_answers_is_always_entered()
    {
        var circuit = new OutboundCircuit(new ManualTime());
        circuit.TryEnter("smtp:relay:25").Should().BeTrue();
        circuit.TryEnter("smtp:relay:25").Should().BeTrue("callers aren't serialised while the target answers");
        circuit.Succeeded("smtp:relay:25");
        circuit.TryEnter("smtp:relay:25").Should().BeTrue();
    }

    [Fact]
    public void A_failure_backs_the_target_off_and_one_probe_goes_when_the_back_off_ends()
    {
        var time = new ManualTime();
        var circuit = new OutboundCircuit(time);
        circuit.TryEnter("t").Should().BeTrue();
        circuit.Failed("t");

        circuit.TryEnter("t").Should().BeFalse("it fails fast while backing off");
        time.Now += OutboundCircuit.FirstBackOff - TimeSpan.FromSeconds(1);
        circuit.TryEnter("t").Should().BeFalse();
        time.Now += TimeSpan.FromSeconds(1);
        circuit.TryEnter("t").Should().BeTrue("the back-off is over: one probe");
        circuit.TryEnter("t").Should().BeFalse("the others fail fast while the probe runs");

        circuit.Succeeded("t");
        circuit.TryEnter("t").Should().BeTrue();
        circuit.TryEnter("t").Should().BeTrue();
    }

    [Fact]
    public void The_back_off_doubles_up_to_ten_minutes()
    {
        var time = new ManualTime();
        var circuit = new OutboundCircuit(time);
        var seen = new List<double>();
        for (var i = 0; i < 6; i++)
        {
            circuit.Failed("t");   // the first send, then each probe, fails
            var waited = TimeSpan.Zero;
            while (!circuit.TryEnter("t") && waited < TimeSpan.FromHours(1))
            {
                time.Now += TimeSpan.FromSeconds(30);
                waited += TimeSpan.FromSeconds(30);
            }
            seen.Add(waited.TotalMinutes);
        }
        seen.Should().Equal(1, 2, 4, 8, 10, 10);
    }

    [Fact]
    public void Targets_are_backed_off_separately()
    {
        var circuit = new OutboundCircuit(new ManualTime());
        circuit.Failed("smtp:old-relay:25");
        circuit.TryEnter("smtp:old-relay:25").Should().BeFalse();
        circuit.TryEnter("smtp:new-relay:25").Should().BeTrue("a changed relay is tried at once");
    }

    [Fact]
    public void A_released_probe_hands_the_turn_back_and_leaves_the_back_off_as_it_was(/* BUG-607 */)
    {
        var time = new ManualTime();
        var circuit = new OutboundCircuit(time);
        for (var i = 0; i < 3; i++) circuit.Failed("t");
        time.Now += OutboundCircuit.FirstBackOff;
        circuit.TryEnter("t").Should().BeTrue("the probe");
        circuit.TryEnter("t").Should().BeFalse();

        circuit.Release("t");   // say the caller cancelled it
        circuit.TryEnter("t").Should().BeTrue("the next send is the probe, not ten minutes later");
        circuit.TryEnter("t").Should().BeFalse("still one at a time: the back-off didn't end");

        circuit.Failed("t");
        time.Now += OutboundCircuit.FirstBackOff;
        circuit.TryEnter("t").Should().BeFalse("the release didn't reset the doubling");
        time.Now += OutboundCircuit.FirstBackOff;
        circuit.TryEnter("t").Should().BeTrue();
    }

    [Fact]
    public void A_probe_that_never_reports_doesnt_hold_the_target_shut_for_good()
    {
        var time = new ManualTime();
        var circuit = new OutboundCircuit(time);
        circuit.Failed("t");
        time.Now += OutboundCircuit.FirstBackOff;
        circuit.TryEnter("t").Should().BeTrue();
        time.Now += OutboundCircuit.MaxBackOff;
        circuit.TryEnter("t").Should().BeTrue("a probe's turn lasts at most the longest back-off");
    }
}
