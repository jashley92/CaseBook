using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using Xunit;

namespace IncidentManager.UnitTests;

public class IntegrityMonitorTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 16, 0, 0, 0, TimeSpan.Zero);
    private static ChainVerificationResult Valid => ChainVerificationResult.Valid;
    private static ChainVerificationResult Broken => ChainVerificationResult.Broken(7, "hash mismatch");

    [Fact]
    public void Each_recorded_result_raises_changed_after_current_is_set_and_a_throwing_listener_is_ignored(/* BUG-332 */)
    {
        var m = new IntegrityMonitor();
        var seen = new List<bool?>();
        m.Changed += () => throw new InvalidOperationException("a circuit that's gone");
        m.Changed += () => seen.Add(m.Current?.IsValid);

        m.RecordResult(Broken, T0).Should().BeTrue("a listener's failure doesn't reach the verifier or change the alert");
        m.RecordResult(Valid, T0.AddMinutes(5)).Should().BeFalse();

        seen.Should().Equal(false, true);
    }

    [Fact]
    public void A_valid_result_never_alerts_and_records_current()
    {
        var m = new IntegrityMonitor();
        m.RecordResult(Valid, T0).Should().BeFalse();
        m.Current!.IsValid.Should().BeTrue();
        m.Current.CheckedAtUtc.Should().Be(T0);
    }

    [Fact]
    public void First_break_alerts_but_subsequent_broken_cycles_do_not()
    {
        var m = new IntegrityMonitor();

        m.RecordResult(Broken, T0).Should().BeTrue("the first detection of a break raises the alarm");
        m.RecordResult(Broken, T0.AddMinutes(5)).Should().BeFalse("still broken — don't re-alarm every cycle");
        m.RecordResult(Broken, T0.AddMinutes(10)).Should().BeFalse();

        m.Current!.IsValid.Should().BeFalse();
        m.Current.FirstBrokenSequence.Should().Be(7);
    }

    [Fact]
    public void Recovery_resets_the_latch_so_a_later_break_re_alerts()
    {
        var m = new IntegrityMonitor();

        m.RecordResult(Broken, T0).Should().BeTrue();
        m.RecordResult(Valid, T0.AddHours(1)).Should().BeFalse("recovery is not an alarm");
        m.RecordResult(Broken, T0.AddHours(2)).Should().BeTrue("a fresh break after recovery alarms again");
    }
}
