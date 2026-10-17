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
    public void Each_recorded_result_raises_changed_after_current_is_set_and_a_throwing_listener_is_ignored(/* BUG-332 */)
    {
        var m = new EvidenceIntegrityMonitor();
        var seen = new List<bool?>();
        m.Changed += () => throw new InvalidOperationException("a circuit that's gone");
        m.Changed += () => seen.Add(m.Current?.IsClean);

        m.RecordResult(Drift(), T0).Should().BeTrue("a listener's failure doesn't reach the verifier or change the alert");
        m.RecordResult(Clean(), T0.AddHours(24)).Should().BeFalse();

        seen.Should().Equal(false, true);
    }

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

    // PROD-53: a run over one share of the files.
    private static EvidenceVerificationResult Share(Guid[] checkedIds, Guid[] known, params EvidenceDrift[] drifts) =>
        new(checkedIds.Length, drifts, T0, checkedIds.ToHashSet(), known.ToHashSet());

    [Fact]
    public void A_drift_found_in_one_share_stays_until_that_file_is_checked_again(/* PROD-53 */)
    {
        var m = new EvidenceIntegrityMonitor();
        var other = Guid.NewGuid();
        Guid[] all = [Shot, Memo, other];

        m.RecordResult(Share([Shot], all, D(Shot)), T0).Should().BeTrue();
        m.RecordResult(Share([Memo], all), T0.AddDays(1)).Should().BeFalse("the drift is still there, so no new alarm");
        m.Current!.IsClean.Should().BeFalse("a run that didn't check the drifted file doesn't clear it");
        m.Current.Drifts.Select(d => d.EvidenceId).Should().Equal(Shot);
        m.Current.CheckedCount.Should().Be(1);
        m.Current.TotalCount.Should().Be(3);

        m.RecordResult(Share([Memo, other], all, D(Memo, EvidenceDriftKind.Missing)), T0.AddDays(2))
            .Should().BeTrue("a second file's drift alarms while the first persists");
        m.Current.Drifts.Select(d => d.EvidenceId).Should().BeEquivalentTo([Shot, Memo]);

        m.RecordResult(Share([Shot], all), T0.AddDays(3)).Should().BeFalse();
        m.Current.Drifts.Select(d => d.EvidenceId).Should().Equal(Memo);   // Shot checked clean
        m.RecordResult(Share([other], [Shot, other]), T0.AddDays(4)).Should().BeFalse();
        m.Current.IsClean.Should().BeTrue("a drifted file whose evidence was removed is dropped");

        m.RecordResult(Share([Shot], all, D(Shot)), T0.AddDays(5)).Should().BeTrue("one that cleared and came back alarms again");
        m.RecordResult(Clean(3), T0.AddDays(6)).Should().BeFalse();
        m.Current.IsClean.Should().BeTrue("a run over every file replaces what earlier shares found");
    }

    [Theory]
    [InlineData(7, 24, 7)]
    [InlineData(1, 24, 1)]
    [InlineData(7, 48, 3)]      // a run every 2 days: every file within 6 days
    [InlineData(1, 6, 4)]       // every 6 hours: every file each day
    [InlineData(7, 200, 1)]     // runs further apart than the pass: every file every run
    [InlineData(0, 24, 1)]
    public void The_files_are_split_so_each_is_checked_within_the_pass(int passDays, int intervalHours, int shares)
    {
        var interval = TimeSpan.FromHours(intervalHours);
        EvidenceIntegrityVerifier.Shares(passDays, interval).Should().Be(shares);
        (interval * shares).Should().BeLessThanOrEqualTo(TimeSpan.FromDays(Math.Max(passDays, 1)) + (shares == 1 ? interval : TimeSpan.Zero));
    }

    [Fact]
    public void Each_share_comes_round_once_a_pass_and_files_spread_evenly(/* PROD-53 */)
    {
        var interval = TimeSpan.FromHours(24);
        var start = new DateTimeOffset(2026, 10, 17, 0, 0, 0, TimeSpan.Zero);
        Enumerable.Range(0, 7).Select(d => EvidenceIntegrityVerifier.ShareDue(start.AddDays(d).AddHours(13), interval, 7))
            .Should().BeEquivalentTo(Enumerable.Range(0, 7), "seven consecutive days check each of the seven shares once");
        EvidenceIntegrityVerifier.ShareDue(start.AddHours(1), interval, 7)
            .Should().Be(EvidenceIntegrityVerifier.ShareDue(start.AddHours(23), interval, 7), "one share per interval, restart or not");

        var ids = Enumerable.Range(0, 7_000).Select(_ => Guid.NewGuid()).ToList();
        ids.All(id => EvidenceIntegrityVerifier.ShareOf(id, 7) == EvidenceIntegrityVerifier.ShareOf(id, 7)).Should().BeTrue();
        ids.GroupBy(id => EvidenceIntegrityVerifier.ShareOf(id, 7)).Select(g => g.Count())
            .Should().HaveCount(7).And.OnlyContain(n => n > 800 && n < 1_200, "random ids spread about evenly");
        EvidenceIntegrityVerifier.ShareOf(Guid.NewGuid(), 1).Should().Be(0);
    }
}
