#Requires -Version 5.1
<#
.SYNOPSIS
    Records CaseBook's latest database backup where Diagnostics reads it, from SQL Server's own backup history: for a
    server whose backups an organization's backup product takes.

.DESCRIPTION
    SQL Server records every backup of a database in msdb, whatever takes it: a backup product (through SQL Server's
    backup interface), a SQL Agent job, or Backup-CaseBook.ps1. This reads the newest full or differential backup of
    CaseBook's database and writes it to the status file (BackupStatus:FilePath): when it finished, its size, its kind and
    what took it. CaseBook takes no backup itself, so the product's backup chain is untouched.

    It covers the database only. Keep the folders that go with it (Administration > Diagnostics > Backup set) in the
    product's file backups too, and prove the two restore together with Test-CaseBookRestore.ps1.

    Run it after each backup (a backup product's post-backup step, or a schedule), as an account that can read msdb
    (the msdb public role is enough for backupset; db_datareader on msdb is safest) and write the status file.

.PARAMETER SitePath
    The CaseBook site folder (where appsettings.Production.json is). Default C:\inetpub\casebook.

.PARAMETER Register
    Creates (or replaces) a scheduled task that runs this every hour, as -TaskAccount (default SYSTEM).

.EXAMPLE
    .\Update-CaseBookBackupStatus.ps1
.EXAMPLE
    .\Update-CaseBookBackupStatus.ps1 -Register -TaskAccount 'CONTOSO\svc-casebook-bk$'
#>
param(
    [string] $SitePath = 'C:\inetpub\casebook',
    [switch] $Register,
    [string] $TaskAccount = 'SYSTEM',
    # SQL Server sign-in, where Windows authentication isn't possible (asked for with Get-Credential; never stored).
    [System.Management.Automation.PSCredential] $SqlCredential
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\CaseBookSql.ps1')
. (Join-Path $PSScriptRoot 'lib\CaseBookStamp.ps1')
. (Join-Path $PSScriptRoot 'lib\CaseBookBackup.ps1')

if ($Register) {
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 1)
    Register-CaseBookTask -Name 'backup status' -Script $MyInvocation.MyCommand.Path -Arguments "-SitePath `"$SitePath`"" `
        -Trigger $trigger -Account $TaskAccount
    return
}

$site = Read-CaseBookSite $SitePath
$statusFile = Get-CaseBookPath $site 'BackupStatus:FilePath'
if (-not $statusFile) { throw 'BackupStatus:FilePath isn''t set in appsettings.Production.json, so there''s nowhere to record the backup.' }
$db = Get-CaseBookDatabase $site

$conn = New-CaseBookSqlConnection -SqlInstance $db.Instance -DbName 'msdb' -SqlCredential $SqlCredential
try {
    # msdb keeps server local time: it's converted to UTC with the server's current offset.
    $rows = Invoke-CaseBookSqlQuery -Connection $conn -Parameters @{ '@db' = $db.Name } -Sql @'
SELECT TOP 1
    DATEADD(MINUTE, DATEDIFF(MINUTE, GETDATE(), GETUTCDATE()), b.backup_finish_date) AS finished_utc,
    b.type, b.is_copy_only, b.backup_size, b.compressed_backup_size, m.device_type, m.physical_device_name
FROM msdb.dbo.backupset b
JOIN msdb.dbo.backupmediafamily m ON m.media_set_id = b.media_set_id
WHERE b.database_name = @db AND b.type IN ('D', 'I')
ORDER BY b.backup_finish_date DESC
'@
} finally { $conn.Dispose() }

if ($rows.Count -eq 0) {
    Write-Warning "SQL Server has no record of a full or differential backup of $($db.Name). Nothing recorded."
    exit 1
}
$b = $rows[0]
$finished = Get-CaseBookStamp -Format 'yyyy-MM-ddTHH:mm:ssZ' -When ([datetime]$b.finished_utc)
$kind = $(if ($b.type -eq 'D') { 'full' } else { 'differential' }) + $(if ($b.is_copy_only) { ', copy-only' } else { '' })
# 7 is a virtual device (a backup product), 9 a URL, 2 a disk file.
$by = switch ([int]$b.device_type) { 7 { 'a backup product (SQL Server backup history)' } 9 { 'a backup to URL (SQL Server backup history)' } default { 'a disk backup (SQL Server backup history)' } }
$size = if ($b.compressed_backup_size) { [long]$b.compressed_backup_size } else { [long]$b.backup_size }

# Keep a newer time already there (Backup-CaseBook.ps1 may have written one).
$current = $null
if (Test-Path $statusFile) { try { $current = (Get-Content $statusFile -Raw -Encoding UTF8 | ConvertFrom-Json).lastBackupUtc } catch { $current = $null } }
if ($current -and ([datetime]$current).ToUniversalTime() -ge ([datetime]$b.finished_utc)) {
    Write-Host "The status file already records a backup at $current, as new as SQL Server's latest ($finished). Unchanged." -ForegroundColor Gray
    exit 0
}
Set-CaseBookBackupStatus -Path $statusFile -Values @{
    lastBackupUtc = $finished; lastBackupSizeBytes = $size; lastBackupBy = $by
    lastBackupSet = "$kind backup: $($b.physical_device_name)"
}
Write-Host "Recorded the $kind backup of $($db.Name) that finished $finished ($([math]::Round($size / 1MB, 1)) MB, by $by)." -ForegroundColor Green
exit 0
