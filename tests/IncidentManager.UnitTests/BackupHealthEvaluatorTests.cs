using FluentAssertions;
using IncidentManager.Application.Ops;
using Xunit;

namespace IncidentManager.UnitTests;

public class BackupHealthEvaluatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 14, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan BackupMaxAge = TimeSpan.FromHours(24);
    private static readonly TimeSpan RestoreMaxAge = TimeSpan.FromDays(35);

    private static BackupHealthReport Eval(BackupStatusFile? status, bool configured = true) =>
        BackupHealthEvaluator.Evaluate(status, Now, BackupMaxAge, RestoreMaxAge, "status.json", configured);

    [Fact]
    public void Not_configured_is_reported_distinctly_and_is_not_a_failure()
    {
        var report = Eval(null, configured: false);
        report.Overall.Should().Be(BackupHealthState.NotConfigured);
        report.Items.Should().ContainSingle();
    }

    [Fact]
    public void Configured_but_no_file_reads_as_missing()
    {
        var report = Eval(null, configured: true);
        report.Overall.Should().Be(BackupHealthState.Missing);
    }

    [Fact]
    public void Recent_backup_and_restore_are_fresh()
    {
        var report = Eval(new BackupStatusFile
        {
            LastBackupUtc = Now.AddHours(-3),
            LastVerifiedRestoreUtc = Now.AddDays(-10),
        });

        report.Overall.Should().Be(BackupHealthState.Ok);
        report.Items.Should().OnlyContain(i => i.State == BackupHealthState.Ok);
    }

    [Fact]
    public void A_backup_older_than_the_threshold_is_stale()
    {
        var report = Eval(new BackupStatusFile
        {
            LastBackupUtc = Now.AddHours(-30),           // > 24h
            LastVerifiedRestoreUtc = Now.AddDays(-10),   // fresh
        });

        report.Overall.Should().Be(BackupHealthState.Stale);
        report.Items.Single(i => i.Label == "Last successful backup").State.Should().Be(BackupHealthState.Stale);
        report.Items.Single(i => i.Label == "Last verified restore").State.Should().Be(BackupHealthState.Ok);
    }

    [Fact]
    public void A_never_verified_restore_is_missing_and_dominates_a_stale_backup()
    {
        var report = Eval(new BackupStatusFile
        {
            LastBackupUtc = Now.AddHours(-30),   // stale
            LastVerifiedRestoreUtc = null,       // never recorded
        });

        // Missing (no data) ranks above Stale (old data) for the overall verdict.
        report.Overall.Should().Be(BackupHealthState.Missing);
        report.Items.Single(i => i.Label == "Last verified restore").State.Should().Be(BackupHealthState.Missing);
    }

    [Fact]
    public void A_future_timestamp_is_treated_as_stale_not_fresh()
    {
        var report = Eval(new BackupStatusFile
        {
            LastBackupUtc = Now.AddHours(2),             // clock skew / bad write
            LastVerifiedRestoreUtc = Now.AddDays(-1),
        });

        report.Items.Single(i => i.Label == "Last successful backup").State.Should().Be(BackupHealthState.Stale);
    }

    [Fact]
    public void The_operator_note_is_surfaced_and_trimmed()
    {
        var report = Eval(new BackupStatusFile
        {
            LastBackupUtc = Now.AddHours(-1),
            LastVerifiedRestoreUtc = Now.AddDays(-1),
            Note = "  Nightly full + 15-min logs; monthly restore verified.  ",
        });

        report.Note.Should().Be("Nightly full + 15-min logs; monthly restore verified.");
    }
}
