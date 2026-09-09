namespace IncidentManager.Application.Ops;

/// <summary>Health state of a single backup/restore signal, shown in the Admin Diagnostics panel (H-04).</summary>
public enum BackupHealthState
{
    /// <summary>Fresh — within the configured cadence threshold.</summary>
    Ok,
    /// <summary>Present but older than the threshold — attention needed.</summary>
    Stale,
    /// <summary>Expected but not recorded (status file present, value absent/unparseable).</summary>
    Missing,
    /// <summary>No status source configured (e.g. development).</summary>
    NotConfigured
}

/// <summary>
/// The status document the out-of-band backup/restore jobs write for the app to read (H-04).
/// The app never writes it — SQL Agent / the restore-verification job owns it — so the signal
/// survives even while the database itself is being restored. See docs/OPERATIONS.md §1.3.
/// </summary>
public sealed record BackupStatusFile
{
    public DateTimeOffset? LastBackupUtc { get; init; }
    public DateTimeOffset? LastVerifiedRestoreUtc { get; init; }
    public long? LastBackupSizeBytes { get; init; }
    public string? Note { get; init; }
}

/// <summary>One evaluated signal (e.g. "Last successful backup") with its freshness verdict.</summary>
public sealed record BackupHealthItem(string Label, BackupHealthState State, string Detail);

/// <summary>The rolled-up backup/restore health surfaced in Diagnostics.</summary>
public sealed record BackupHealthReport(
    BackupHealthState Overall,
    string Source,
    IReadOnlyList<BackupHealthItem> Items,
    string? Note);

/// <summary>
/// Pure evaluation of backup/restore freshness against configured cadence thresholds (H-04).
/// Filesystem- and config-free so it is deterministic and unit-testable; the hosting layer
/// resolves the path, reads/parses the file, and passes the result in.
/// </summary>
public static class BackupHealthEvaluator
{
    /// <summary>
    /// Evaluates the status document as of <paramref name="now"/>. A <paramref name="status"/> of
    /// <c>null</c> means the source was not configured or could not be read — distinguished by
    /// <paramref name="configured"/>.
    /// </summary>
    public static BackupHealthReport Evaluate(
        BackupStatusFile? status,
        DateTimeOffset now,
        TimeSpan backupMaxAge,
        TimeSpan restoreMaxAge,
        string source,
        bool configured)
    {
        if (!configured)
            return new BackupHealthReport(
                BackupHealthState.NotConfigured, source,
                [new BackupHealthItem("Backup status source", BackupHealthState.NotConfigured,
                    "no status file configured (BackupStatus:FilePath) — expected in production")],
                null);

        if (status is null)
            return new BackupHealthReport(
                BackupHealthState.Missing, source,
                [new BackupHealthItem("Backup status source", BackupHealthState.Missing,
                    "status file not found or unreadable at the configured path")],
                null);

        var backup = Freshness("Last successful backup", status.LastBackupUtc, now, backupMaxAge);
        var restore = Freshness("Last verified restore", status.LastVerifiedRestoreUtc, now, restoreMaxAge);
        var items = new List<BackupHealthItem> { backup, restore };

        // Overall = the worst signal. Missing (no data) and Stale (old data) are both problems;
        // rank Missing above Stale so "nothing recorded" reads as the more serious verdict.
        var overall = new[] { backup.State, restore.State }.Contains(BackupHealthState.Missing)
            ? BackupHealthState.Missing
            : new[] { backup.State, restore.State }.Contains(BackupHealthState.Stale)
                ? BackupHealthState.Stale
                : BackupHealthState.Ok;

        return new BackupHealthReport(overall, source, items, string.IsNullOrWhiteSpace(status.Note) ? null : status.Note.Trim());
    }

    private static BackupHealthItem Freshness(string label, DateTimeOffset? at, DateTimeOffset now, TimeSpan maxAge)
    {
        if (at is null)
            return new BackupHealthItem(label, BackupHealthState.Missing, "not recorded");

        var age = now - at.Value;
        var when = $"{Humanize(age)} ago ({at.Value.UtcDateTime:yyyy-MM-dd HH:mm} UTC)";
        // A future timestamp (clock skew / bad write) is suspect — treat as stale, not fresh.
        if (age < TimeSpan.Zero)
            return new BackupHealthItem(label, BackupHealthState.Stale, $"timestamp is in the future ({at.Value.UtcDateTime:yyyy-MM-dd HH:mm} UTC)");

        return age <= maxAge
            ? new BackupHealthItem(label, BackupHealthState.Ok, when)
            : new BackupHealthItem(label, BackupHealthState.Stale, $"{when} — older than the {Humanize(maxAge)} threshold");
    }

    private static string Humanize(TimeSpan span)
    {
        span = span.Duration();
        if (span.TotalDays >= 1) return $"{(int)span.TotalDays}d {span.Hours}h";
        if (span.TotalHours >= 1) return $"{(int)span.TotalHours}h {span.Minutes}m";
        if (span.TotalMinutes >= 1) return $"{(int)span.TotalMinutes}m";
        return $"{(int)span.TotalSeconds}s";
    }
}
