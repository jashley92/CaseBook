#Requires -Version 5.1
<#
.SYNOPSIS
    Backs up CaseBook as one set: the database, and the folders that go with it (keys, Data Protection keys, seals,
    reports, branding, report templates), plus the evidence store; then records it where Diagnostics reads it.

.DESCRIPTION
    For a server without a backup product. If your organization's backup product already backs up SQL Server and these
    folders, don't schedule this: use Update-CaseBookBackupStatus.ps1 instead, which reads SQL Server's own backup history,
    and keep the folders (Administration > Diagnostics > Backup set lists them) in the product's file backups. If you run
    this beside a product anyway, add -CopyOnly so its backup chain isn't disturbed.

    Each run makes a folder <Destination>\CaseBook-<yyyyMMdd-HHmm> holding:
      db\<database>.bak       a full backup WITH CHECKSUM, then checked with RESTORE VERIFYONLY
      files\<label>\          a copy of each folder of the backup set
      backup-set.json         what's in the set: the database, each folder (files and bytes), the evidence mirror
    Evidence only ever grows, so it's copied into one mirror, <Destination>\evidence, that every set shares; a set and
    the mirror together are a whole CaseBook.

    The database is in the FULL recovery model (the installer sets it), so its transaction log is cleared only by a log
    backup: -Log takes one, into <Destination>\log, and -Register schedules one every -LogEveryMinutes (15) beside the
    nightly set. Without them the log grows until the disk is full. That gives a recovery point of 15 minutes; a
    database in the SIMPLE model has no log backups (its recovery point is the last nightly set), and -Log does nothing.

    A run succeeds only when the backup, its verification and every copy succeed. Then lastBackupUtc, its size and the
    set's folder go into the status file (BackupStatus:FilePath). A failure writes the reason and its time instead,
    which Diagnostics and the overview show as Failed, and exits with code 1. The newest -Keep sets are kept.

    Run it as an account that can back up the database (db_backupoperator, or sysadmin), read the site's data folders,
    and write to -Destination. SQL Server writes the .bak itself, as its service account, so that account needs write
    to the db folder too (or give -DatabaseBackupFolder, a folder as SQL Server sees it). The backup holds the keys
    folder: keep -Destination as tightly locked down as the data root.

.PARAMETER SitePath
    The CaseBook site folder (where appsettings.Production.json is). Default C:\inetpub\casebook.

.PARAMETER Destination
    Where the backup sets go: a local folder or a share.

.PARAMETER Keep
    How many sets to keep (default 14). Older ones are removed after a successful run. The evidence mirror is kept.

.PARAMETER CopyOnly
    A COPY_ONLY backup, which doesn't reset another product's differential base.

.PARAMETER DatabaseBackupFolder
    Where SQL Server writes the .bak, as SQL Server sees the path, when it isn't this server (default: the set's db folder).
    Files written there aren't removed by -Keep: clear them as your SQL Server's maintenance does.

.PARAMETER Log
    A transaction-log backup only, into <Destination>\log (or -DatabaseBackupFolder). Logs older than the oldest set
    kept are removed. Not with -CopyOnly: a backup product that backs up the database takes its log backups too.

.PARAMETER Register
    Creates (or replaces) a nightly scheduled task that runs this script with the same -SitePath, -Destination, -Keep and
    -CopyOnly, at -At, and (unless -CopyOnly, or -LogEveryMinutes 0) a log backup task every -LogEveryMinutes, as
    -TaskAccount (default SYSTEM; a gMSA such as CONTOSO\svc-casebook-bk$ needs no password). The tasks run the copy of
    this script kept beside the site (<site>-deploy), which upgrades keep current, when there is one.

.EXAMPLE
    .\Backup-CaseBook.ps1 -Destination \\backup01\casebook
.EXAMPLE
    .\Backup-CaseBook.ps1 -Destination \\backup01\casebook -Register -TaskAccount 'CONTOSO\svc-casebook-bk$' -At 01:30
#>
param(
    [string] $SitePath = 'C:\inetpub\casebook',
    [Parameter(Mandatory)] [string] $Destination,
    [int] $Keep = 14,
    [switch] $CopyOnly,
    [string] $DatabaseBackupFolder,
    [switch] $Log,
    [switch] $Register,
    [int] $LogEveryMinutes = 15,
    [string] $TaskAccount = 'SYSTEM',
    # SQL Server sign-in, where Windows authentication isn't possible (asked for with Get-Credential; never stored).
    [System.Management.Automation.PSCredential] $SqlCredential,
    [string] $At = '01:30'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\CaseBookSql.ps1')
. (Join-Path $PSScriptRoot 'lib\CaseBookStamp.ps1')
. (Join-Path $PSScriptRoot 'lib\CaseBookBackup.ps1')

if ($Log -and $CopyOnly) { throw '-Log with -CopyOnly: a backup product that backs up the database takes its log backups too, and two log chains break each other.' }

if ($Register) {
    $arguments = "-SitePath `"$SitePath`" -Destination `"$Destination`" -Keep $Keep" + $(if ($CopyOnly) { ' -CopyOnly' } else { '' }) +
                 $(if ($DatabaseBackupFolder) { " -DatabaseBackupFolder `"$DatabaseBackupFolder`"" } else { '' })
    Register-CaseBookTask -Name 'nightly backup' -Script $MyInvocation.MyCommand.Path -SitePath $SitePath -Arguments $arguments `
        -Trigger (New-ScheduledTaskTrigger -Daily -At $At) -Account $TaskAccount
    if (-not $CopyOnly -and $LogEveryMinutes -gt 0) {
        $logTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $LogEveryMinutes)
        Register-CaseBookTask -Name 'log backup' -Script $MyInvocation.MyCommand.Path -SitePath $SitePath -Arguments "$arguments -Log" `
            -Trigger $logTrigger -Account $TaskAccount
    }
    return
}

$site = Read-CaseBookSite $SitePath
$statusFile = Get-CaseBookPath $site 'BackupStatus:FilePath'
if (-not $statusFile) { Write-Warning 'BackupStatus:FilePath isn''t set, so Diagnostics won''t see this backup. Set it in appsettings.Production.json.' }
$db = Get-CaseBookDatabase $site
$started = Get-Date
$stamp = Get-CaseBookStamp -Format 'yyyyMMdd-HHmm' -When $started
$set = Join-Path $Destination "CaseBook-$stamp"

if ($Log) {
    try {
        $conn = New-CaseBookSqlConnection -SqlInstance $db.Instance -DbName 'master' -SqlCredential $SqlCredential
        try {
            $model = Invoke-CaseBookSqlScalar -Connection $conn -Sql 'SELECT recovery_model_desc FROM sys.databases WHERE name = @n' -Parameters @{ '@n' = $db.Name }
            if ("$model" -eq 'SIMPLE') { Write-Host "$($db.Name) is in the SIMPLE recovery model: it has no log to back up." -ForegroundColor Gray; exit 0 }
            # A log backup needs a full one before it (since the database was created, or last switched to FULL).
            $base = Invoke-CaseBookSqlScalar -Connection $conn -Sql 'SELECT COUNT(*) FROM sys.database_recovery_status WHERE database_id = DB_ID(@n) AND last_log_backup_lsn IS NOT NULL' -Parameters @{ '@n' = $db.Name }
            if ([int]$base -eq 0) { Write-Host 'No full backup to follow yet, so no log backup: the nightly set comes first.' -ForegroundColor Yellow; exit 0 }
            $logFolder = if ($DatabaseBackupFolder) { $DatabaseBackupFolder } else { Join-Path $Destination 'log' }
            if (-not $DatabaseBackupFolder) { New-Item -ItemType Directory -Force -Path $logFolder | Out-Null }
            $sep = if ($logFolder.Contains('/')) { '/' } else { '\' }
            $trn = $logFolder.TrimEnd('\', '/') + $sep + "$($db.Name)-$(Get-CaseBookStamp -Format 'yyyyMMdd-HHmmss' -When $started).trn"
            $express = [int](Invoke-CaseBookSqlScalar -Connection $conn -Sql "SELECT CAST(SERVERPROPERTY('EngineEdition') AS int)") -eq 4
            $with = @('CHECKSUM', 'INIT'); if (-not $express) { $with += 'COMPRESSION' }
            $null = Invoke-CaseBookSqlQuery -Connection $conn -Sql ("BACKUP LOG $(Get-SqlName $db.Name) TO DISK = @trn WITH " + ($with -join ', ')) -Parameters @{ '@trn' = $trn }
        } finally { $conn.Dispose() }
        # Logs older than the oldest set kept can't be used by any set kept.
        if (-not $DatabaseBackupFolder) {
            $oldest = @(Get-ChildItem -Path $Destination -Directory -Filter 'CaseBook-*' | Where-Object { Test-Path (Join-Path $_.FullName 'backup-set.json') } |
                Sort-Object Name | Select-Object -First 1)
            if ($oldest.Count -eq 1) {
                Get-ChildItem -Path $logFolder -Filter '*.trn' | Where-Object { $_.LastWriteTime -lt $oldest[0].CreationTime } | Remove-Item -Force
            }
        }
        if ($statusFile) { Set-CaseBookBackupStatus -Path $statusFile -Values @{ lastLogBackupUtc = Get-UtcStamp } }
        Write-Host "Log backup: $trn" -ForegroundColor Green
        exit 0
    }
    catch {
        $reason = "Log backup failed: $($_.Exception.Message)"
        Write-Host $reason -ForegroundColor Red
        if ($statusFile) {
            try { Set-CaseBookBackupStatus -Path $statusFile -Values @{ lastLogBackupFailedUtc = Get-UtcStamp; lastLogBackupError = $reason } }
            catch { Write-Warning "The failure couldn't be recorded in $statusFile either: $($_.Exception.Message)" }
        }
        exit 1
    }
}

try {
    New-Item -ItemType Directory -Force -Path (Join-Path $set 'db') | Out-Null
    $bakFolder = if ($DatabaseBackupFolder) { $DatabaseBackupFolder } else { Join-Path $set 'db' }
    $bak = Join-Path $bakFolder "$($db.Name).bak"
    if ($DatabaseBackupFolder) { $bak = $bakFolder.TrimEnd('\', '/') + $(if ($bakFolder.Contains('/')) { '/' } else { '\' }) + "$($db.Name)-$stamp.bak" }

    Write-Host "Backing up $($db.Name) on $($db.Instance) to $bak" -ForegroundColor Cyan
    $conn = New-CaseBookSqlConnection -SqlInstance $db.Instance -DbName 'master' -SqlCredential $SqlCredential
    try {
        # Express has no backup compression.
        $express = [int](Invoke-CaseBookSqlScalar -Connection $conn -Sql "SELECT CAST(SERVERPROPERTY('EngineEdition') AS int)") -eq 4
        $with = @('CHECKSUM', 'INIT', "NAME = N'CaseBook $stamp'")
        if (-not $express) { $with += 'COMPRESSION' }
        if ($CopyOnly) { $with += 'COPY_ONLY' }
        $null = Invoke-CaseBookSqlQuery -Connection $conn -Sql ("BACKUP DATABASE $(Get-SqlName $db.Name) TO DISK = @bak WITH " + ($with -join ', ')) -Parameters @{ '@bak' = $bak }
        $null = Invoke-CaseBookSqlQuery -Connection $conn -Sql 'RESTORE VERIFYONLY FROM DISK = @bak WITH CHECKSUM' -Parameters @{ '@bak' = $bak }
        $row = (Invoke-CaseBookSqlQuery -Connection $conn -Parameters @{ '@db' = $db.Name } -Sql @'
SELECT TOP 1 b.backup_size, b.compressed_backup_size
FROM msdb.dbo.backupset b WHERE b.database_name = @db AND b.type = 'D' ORDER BY b.backup_finish_date DESC
'@)[0]
        $dbBytes = if ($row.compressed_backup_size) { [long]$row.compressed_backup_size } else { [long]$row.backup_size }
    } finally { $conn.Dispose() }
    Write-Host "  Database backed up and verified ($([math]::Round($dbBytes / 1MB, 1)) MB)." -ForegroundColor Gray

    $folders = @()
    foreach ($f in Get-CaseBookBackupFolders $site) {
        if (-not (Test-Path $f.Path)) {
            Write-Host "  $($f.Label): $($f.Path) isn't there; nothing to copy." -ForegroundColor Yellow
            $folders += [ordered]@{ label = $f.Label; setting = $f.Key; source = $f.Path; files = 0; bytes = 0; note = 'not there' }
            continue
        }
        $copied = Copy-CaseBookFolder -From $f.Path -To (Join-Path $set "files\$($f.Label)")
        Write-Host "  $($f.Label): $($copied.Files) files" -ForegroundColor Gray
        $folders += [ordered]@{ label = $f.Label; setting = $f.Key; source = $f.Path; files = $copied.Files; bytes = $copied.Bytes }
    }

    # Evidence: one mirror the sets share. Uploads still arriving (.incoming) aren't evidence yet.
    $evidence = Get-CaseBookEvidenceFolder $site
    $mirror = Join-Path $Destination 'evidence'
    $ev = Copy-CaseBookFolder -From $evidence -To $mirror -ExcludeDirs @((Join-Path $evidence '.incoming'))
    Write-Host "  evidence: mirror holds $($ev.Files) files" -ForegroundColor Gray

    $manifest = [ordered]@{
        format = 1
        createdUtc = Get-UtcStamp -When $started
        finishedUtc = Get-UtcStamp
        server = $env:COMPUTERNAME
        site = $site.Folder
        database = [ordered]@{ instance = $db.Instance; name = $db.Name; file = $bak; bytes = $dbBytes; copyOnly = [bool]$CopyOnly; verified = $true }
        folders = $folders
        evidence = [ordered]@{ source = $evidence; mirror = $mirror; files = $ev.Files; bytes = $ev.Bytes }
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $set 'backup-set.json') -Encoding UTF8

    if ($statusFile) {
        Set-CaseBookBackupStatus -Path $statusFile -Values @{
            lastBackupUtc = Get-UtcStamp; lastBackupSizeBytes = $dbBytes + [long](($folders | ForEach-Object { $_.bytes } | Measure-Object -Sum).Sum)
            lastBackupSet = $set; lastBackupBy = 'Backup-CaseBook.ps1'
        }
    }

    # Keep the newest -Keep sets (a set counts once its backup-set.json is written).
    $sets = @(Get-ChildItem -Path $Destination -Directory -Filter 'CaseBook-*' | Where-Object { Test-Path (Join-Path $_.FullName 'backup-set.json') } |
        Sort-Object Name -Descending)
    foreach ($old in ($sets | Select-Object -Skip $Keep)) {
        Remove-Item -LiteralPath $old.FullName -Recurse -Force
        Write-Host "  Removed the old set $($old.Name)." -ForegroundColor Gray
    }
    Write-Host "Backup set complete: $set" -ForegroundColor Green
}
catch {
    $reason = $_.Exception.Message
    Write-Host "Backup failed: $reason" -ForegroundColor Red
    # A set that didn't finish (no backup-set.json) is removed, so it can't be mistaken for one or fill the destination.
    if ((Test-Path $set) -and -not (Test-Path (Join-Path $set 'backup-set.json'))) { Remove-Item -LiteralPath $set -Recurse -Force -ErrorAction SilentlyContinue }
    if ($statusFile) {
        try { Set-CaseBookBackupStatus -Path $statusFile -Values @{ lastBackupFailedUtc = Get-UtcStamp; lastBackupError = $reason } }
        catch { Write-Warning "The failure couldn't be recorded in $statusFile either: $($_.Exception.Message)" }
    }
    exit 1
}
# Robocopy leaves 1 ("files copied") in $LASTEXITCODE, which a scheduled task would read as a failure.
exit 0
