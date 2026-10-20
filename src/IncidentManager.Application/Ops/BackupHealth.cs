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
    NotConfigured,
    /// <summary>The latest attempt failed, after the last success (the jobs record why).</summary>
    Failed,
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

    // deploy\Backup-CaseBook.ps1, Update-CaseBookBackupStatus.ps1 and Test-CaseBookRestore.ps1 also write these.
    /// <summary>Where the last backup is (a backup set's folder, or the device SQL Server's history names).</summary>
    public string? LastBackupSet { get; init; }
    /// <summary>What recorded it: the backup script, or SQL Server's backup history (a backup product's backups).</summary>
    public string? LastBackupBy { get; init; }
    /// <summary>Why the latest backup attempt failed, and when; stale once a later backup succeeds.</summary>
    public string? LastBackupError { get; init; }
    public DateTimeOffset? LastBackupFailedUtc { get; init; }
    /// <summary>The backup set the last verified restore came from, and what its checks found.</summary>
    public string? LastVerifiedRestoreSet { get; init; }
    public string? LastRestoreSummary { get; init; }
    /// <summary>Why the latest restore drill failed, and when; stale once a later drill passes.</summary>
    public string? LastRestoreError { get; init; }
    public DateTimeOffset? LastRestoreFailedUtc { get; init; }
    /// <summary>The last transaction-log backup (Backup-CaseBook.ps1 -Log), and the latest that failed, with why.</summary>
    public DateTimeOffset? LastLogBackupUtc { get; init; }
    public string? LastLogBackupError { get; init; }
    public DateTimeOffset? LastLogBackupFailedUtc { get; init; }
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
        bool configured,
        TimeSpan? logMaxAge = null)
    {
        if (!configured)
            return new BackupHealthReport(
                BackupHealthState.NotConfigured, source,
                [new BackupHealthItem("Backup status source", BackupHealthState.NotConfigured,
                    "no status file configured (BackupStatus:FilePath); one is expected in production")],
                null);

        if (status is null)
            return new BackupHealthReport(
                BackupHealthState.Missing, source,
                [new BackupHealthItem("Backup status source", BackupHealthState.Missing,
                    "status file not found or unreadable at the configured path")],
                null);

        var backup = With(Freshness("Last successful backup", status.LastBackupUtc, now, backupMaxAge),
            Join(status.LastBackupSet is { } set ? $"set {set}" : null, status.LastBackupSizeBytes is { } size ? Size(size) : null,
                status.LastBackupBy is { } by ? $"recorded by {by}" : null));
        var restore = With(Freshness("Last verified restore", status.LastVerifiedRestoreUtc, now, restoreMaxAge),
            Join(status.LastVerifiedRestoreSet is { } rset ? $"from {rset}" : null, status.LastRestoreSummary));
        var items = new List<BackupHealthItem> { backup, restore };
        // Log backups are shown once any is recorded: a database in the SIMPLE model, or one a backup product backs up, has none here.
        if (status.LastLogBackupUtc is not null || status.LastLogBackupFailedUtc is not null)
            items.Insert(1, Freshness("Last log backup", status.LastLogBackupUtc, now, logMaxAge ?? TimeSpan.FromHours(1)));
        // A failure after the last success is the latest news, and the most serious.
        if (Failed(status.LastBackupFailedUtc, status.LastBackupUtc, status.LastBackupError) is { } backupFailed)
            items.Add(new BackupHealthItem("Latest backup attempt", BackupHealthState.Failed, backupFailed));
        if (Failed(status.LastLogBackupFailedUtc, status.LastLogBackupUtc, status.LastLogBackupError) is { } logFailed)
            items.Add(new BackupHealthItem("Latest log backup attempt", BackupHealthState.Failed, logFailed));
        if (Failed(status.LastRestoreFailedUtc, status.LastVerifiedRestoreUtc, status.LastRestoreError) is { } restoreFailed)
            items.Add(new BackupHealthItem("Latest restore drill", BackupHealthState.Failed, restoreFailed));

        // Overall = the worst signal: a failure, then nothing recorded (Missing), then old data (Stale).
        var states = items.Select(i => i.State).ToList();
        var overall = states.Contains(BackupHealthState.Failed) ? BackupHealthState.Failed
            : states.Contains(BackupHealthState.Missing) ? BackupHealthState.Missing
            : states.Contains(BackupHealthState.Stale) ? BackupHealthState.Stale
            : BackupHealthState.Ok;

        return new BackupHealthReport(overall, source, items, string.IsNullOrWhiteSpace(status.Note) ? null : status.Note.Trim());
    }

    private static string? Failed(DateTimeOffset? failedAt, DateTimeOffset? lastSuccess, string? error) =>
        failedAt is { } at && (lastSuccess is null || at > lastSuccess)
            ? $"failed {at.UtcDateTime:yyyy-MM-dd HH:mm} UTC: {(string.IsNullOrWhiteSpace(error) ? "no reason recorded" : error.Trim())}"
            : null;

    private static BackupHealthItem With(BackupHealthItem item, string? more) =>
        string.IsNullOrWhiteSpace(more) || item.State == BackupHealthState.Missing ? item : item with { Detail = $"{item.Detail} · {more}" };

    private static string? Join(params string?[] parts) =>
        parts.Where(p => !string.IsNullOrWhiteSpace(p)) is var some && some.Any() ? string.Join(" · ", some) : null;

    private static string Size(long bytes) => bytes switch
    {
        >= 1L << 30 => $"{bytes / (double)(1L << 30):0.0} GB",
        >= 1L << 20 => $"{bytes / (double)(1L << 20):0.0} MB",
        _ => $"{bytes / 1024.0:0.0} KB",
    };

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
            : new BackupHealthItem(label, BackupHealthState.Stale, $"{when}, older than the {Humanize(maxAge)} threshold");
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
