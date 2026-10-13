using FluentAssertions;
using IncidentManager.Application.Integrity;
using Xunit;

namespace IncidentManager.UnitTests;

public class EvidenceIntegrityMonitorTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 9, 0, 0, 0, TimeSpan.Zero);

    private static EvidenceVerificationResult Clean(int checkedCount = 3) =>
        new(checkedCount, Array.Empty<EvidenceDrift>(), T0);

    private static readonly Guid Shot = Guid.NewGuid(), Memo = Guid.NewGuid();

    private static EvidenceDrift D(Guid id, EvidenceDriftKind kind = EvidenceDriftKind.HashMismatch) =>
        new(id, Guid.Empty, "2026-01_Phishing_Wave", "shot.png", "aaaa", "bbbb", kind, "hash mismatch");

    private static EvidenceVerificationResult Drift(int checkedCount = 3) => new(checkedCount, new[] { D(Shot) }, T0);

    [Fact]
    public void A_new_drift_alerts_even_while_an_older_one_persists(/* REV-09 */)
    {
        var m = new EvidenceIntegrityMonitor();

        m.RecordResult(new(3, new[] { D(Shot) }, T0), T0).Should().BeTrue();
        m.RecordResult(new(3, new[] { D(Shot) }, T0), T0.AddHours(24)).Should().BeFalse();
        m.RecordResult(new(3, new[] { D(Shot), D(Memo) }, T0), T0.AddHours(48)).Should().BeTrue("a second file drifted");
        m.RecordResult(new(3, new[] { D(Shot), D(Memo) }, T0), T0.AddHours(72)).Should().BeFalse();
        m.RecordResult(new(3, new[] { D(Shot, EvidenceDriftKind.Missing), D(Memo) }, T0), T0.AddHours(96))
            .Should().BeTrue("the same file, now a different problem");
    }

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
