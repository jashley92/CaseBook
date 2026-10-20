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

.PARAMETER Register
    Creates (or replaces) a nightly scheduled task that runs this script with the same -SitePath, -Destination, -Keep and
    -CopyOnly, at -At, as -TaskAccount (default SYSTEM; a gMSA such as CONTOSO\svc-casebook-bk$ needs no password).

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
    [switch] $Register,
    [string] $TaskAccount = 'SYSTEM',
    # SQL Server sign-in, where Windows authentication isn't possible (asked for with Get-Credential; never stored).
    [System.Management.Automation.PSCredential] $SqlCredential,
    [string] $At = '01:30'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\CaseBookSql.ps1')
. (Join-Path $PSScriptRoot 'lib\CaseBookStamp.ps1')
. (Join-Path $PSScriptRoot 'lib\CaseBookBackup.ps1')

if ($Register) {
    $arguments = "-SitePath `"$SitePath`" -Destination `"$Destination`" -Keep $Keep" + $(if ($CopyOnly) { ' -CopyOnly' } else { '' }) +
                 $(if ($DatabaseBackupFolder) { " -DatabaseBackupFolder `"$DatabaseBackupFolder`"" } else { '' })
    Register-CaseBookTask -Name 'nightly backup' -Script $MyInvocation.MyCommand.Path -Arguments $arguments `
        -Trigger (New-ScheduledTaskTrigger -Daily -At $At) -Account $TaskAccount
    return
}

$site = Read-CaseBookSite $SitePath
$statusFile = Get-CaseBookPath $site 'BackupStatus:FilePath'
if (-not $statusFile) { Write-Warning 'BackupStatus:FilePath isn''t set, so Diagnostics won''t see this backup. Set it in appsettings.Production.json.' }
$db = Get-CaseBookDatabase $site
$started = Get-Date
$stamp = Get-CaseBookStamp -Format 'yyyyMMdd-HHmm' -When $started
$set = Join-Path $Destination "CaseBook-$stamp"

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
