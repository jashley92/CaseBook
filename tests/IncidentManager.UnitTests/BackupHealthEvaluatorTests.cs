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
    public void A_failure_after_the_last_success_is_the_worst_news_and_says_why()
    {
        var report = Eval(new BackupStatusFile
        {
            LastBackupUtc = Now.AddHours(-26),
            LastBackupFailedUtc = Now.AddHours(-2),
            LastBackupError = "BACKUP DATABASE failed: the share is full",
            LastVerifiedRestoreUtc = Now.AddDays(-10),
        });
        report.Overall.Should().Be(BackupHealthState.Failed);
        report.Items.Should().ContainSingle(i => i.State == BackupHealthState.Failed)
            .Which.Detail.Should().Contain("the share is full");
    }

    [Fact]
    public void A_failure_before_the_last_success_is_old_news()
    {
        var report = Eval(new BackupStatusFile
        {
            LastBackupUtc = Now.AddHours(-1),
            LastBackupFailedUtc = Now.AddHours(-30),
            LastBackupError = "old",
            LastVerifiedRestoreUtc = Now.AddDays(-10),
            LastRestoreFailedUtc = Now.AddDays(-12),
            LastRestoreError = "older",
        });
        report.Overall.Should().Be(BackupHealthState.Ok);
        report.Items.Should().NotContain(i => i.State == BackupHealthState.Failed);
    }

    [Fact]
    public void The_backup_set_and_the_drills_findings_are_shown()
    {
        var report = Eval(new BackupStatusFile
        {
            LastBackupUtc = Now.AddHours(-3), LastBackupSet = @"E:\Backups\CaseBook-20260814-0130", LastBackupSizeBytes = 3L << 30,
            LastBackupBy = "Backup-CaseBook.ps1",
            LastVerifiedRestoreUtc = Now.AddDays(-10), LastVerifiedRestoreSet = "CaseBook-20260804-0130",
            LastRestoreSummary = "Audit chain: passed; Seals: passed",
        });
        report.Items[0].Detail.Should().Contain("CaseBook-20260814-0130").And.Contain("3.0 GB").And.Contain("Backup-CaseBook.ps1");
        report.Items[1].Detail.Should().Contain("CaseBook-20260804-0130").And.Contain("Seals: passed");
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

    [Fact]
    public void Log_backups_show_only_once_recorded_and_go_stale_past_an_hour()
    {
        var none = Eval(new BackupStatusFile { LastBackupUtc = Now.AddHours(-1), LastVerifiedRestoreUtc = Now.AddDays(-1) });
        none.Items.Should().NotContain(i => i.Label == "Last log backup");
        none.Overall.Should().Be(BackupHealthState.Ok);

        var stale = Eval(new BackupStatusFile
        {
            LastBackupUtc = Now.AddHours(-1),
            LastLogBackupUtc = Now.AddMinutes(-75),
            LastVerifiedRestoreUtc = Now.AddDays(-1),
        });
        stale.Items.Single(i => i.Label == "Last log backup").State.Should().Be(BackupHealthState.Stale);
        stale.Overall.Should().Be(BackupHealthState.Stale);
    }

    [Fact]
    public void A_failed_log_backup_is_its_own_failure_and_a_later_log_backup_clears_it_not_a_nightly_one()
    {
        var failed = new BackupStatusFile
        {
            LastBackupUtc = Now.AddMinutes(-10),
            LastLogBackupUtc = Now.AddMinutes(-50),
            LastLogBackupFailedUtc = Now.AddMinutes(-20),
            LastLogBackupError = "Log backup failed: the share is full",
            LastVerifiedRestoreUtc = Now.AddDays(-1),
        };
        var report = Eval(failed);
        report.Overall.Should().Be(BackupHealthState.Failed);
        report.Items.Single(i => i.Label == "Latest log backup attempt").Detail.Should().Contain("the share is full");

        Eval(failed with { LastLogBackupUtc = Now.AddMinutes(-5) }).Overall.Should().Be(BackupHealthState.Ok);
    }
}
