using FluentAssertions;
using IncidentManager.Application.Integrity;
using Xunit;

namespace IncidentManager.UnitTests;

public class EvidenceIntegrityMonitorTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 9, 0, 0, 0, TimeSpan.Zero);

    private static EvidenceVerificationResult Clean(int checkedCount = 3) =>
        new(checkedCount, Array.Empty<EvidenceDrift>(), T0);

    private static EvidenceVerificationResult Drift(int checkedCount = 3) =>
        new(checkedCount, new[]
        {
            new EvidenceDrift(Guid.NewGuid(), Guid.NewGuid(), "2026-01_Phishing_Wave", "shot.png",
                "aaaa", "bbbb", EvidenceDriftKind.HashMismatch, "hash mismatch")
        }, T0);

    [Fact]
    public void A_clean_result_never_alerts_and_records_current()
    {
        var m = new EvidenceIntegrityMonitor();
        m.RecordResult(Clean(), T0).Should().BeFalse();
        m.Current!.IsClean.Should().BeTrue();
        m.Current.CheckedCount.Should().Be(3);
        m.Current.DriftCount.Should().Be(0);
        m.Current.CheckedAtUtc.Should().Be(T0);
    }

    [Fact]
    public void First_drift_alerts_but_subsequent_drift_cycles_do_not()
    {
        var m = new EvidenceIntegrityMonitor();

        m.RecordResult(Drift(), T0).Should().BeTrue("the first detection of drift raises the alarm");
        m.RecordResult(Drift(), T0.AddHours(24)).Should().BeFalse("still drifted — don't re-alarm every pass");
        m.RecordResult(Drift(), T0.AddHours(48)).Should().BeFalse();

        m.Current!.IsClean.Should().BeFalse();
        m.Current.DriftCount.Should().Be(1);
        m.Current.Drifts.Should().ContainSingle().Which.Kind.Should().Be(EvidenceDriftKind.HashMismatch);
    }

    [Fact]
    public void Recovery_resets_the_latch_so_later_drift_re_alerts()
    {
        var m = new EvidenceIntegrityMonitor();

        m.RecordResult(Drift(), T0).Should().BeTrue();
        m.RecordResult(Clean(), T0.AddHours(24)).Should().BeFalse("a clean pass is not an alarm");
        m.RecordResult(Drift(), T0.AddHours(48)).Should().BeTrue("fresh drift after a clean pass alarms again");
    }
}
