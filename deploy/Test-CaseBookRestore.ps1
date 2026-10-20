#Requires -Version 5.1
<#
.SYNOPSIS
    The restore drill: restores CaseBook from a backup into a scratch copy, proves the copy whole, and records the result
    where Diagnostics reads it. A backup counts as verified only when this passes.

.DESCRIPTION
    Two ways to give it the backup:

    From a backup set Backup-CaseBook.ps1 made (-Destination, the newest set; or -BackupSet, one set's folder): the
    database is restored as a scratch database (-ScratchDatabase, default CaseBook_RestoreDrill) on -SqlInstance (default
    the site's own instance; give a recovery server's to test there), and checked with DBCC CHECKDB. The set's folders and
    the evidence mirror are used where they are, read-only.

    From a copy your backup product restored (or mounted): -RestoredDatabase names the database on -SqlInstance, and
    -EvidencePath and -KeysPath where its evidence store and keys folder were restored. It's checked with DBCC CHECKDB and
    left as it is.

    Then casebook-keytool verify-restore checks the copy, as the app would read it:
      - the database opens;
      - the audit trail's hash chain is intact from its first entry to its last;
      - every integrity seal's signature is authentic and its chain head unchanged;
      - every evidence file the database lists is there at its recorded size, and -Sample of them (200; -HashAll for
        every one) hash to their recorded SHA-256;
      - with evidence encryption on, the evidence key opens (with this server's certificate, or -PfxPath / -CertThumbprint
        for a recovery certificate).
    Only when every check passes is lastVerifiedRestoreUtc written to the status file (BackupStatus:FilePath), with the
    set and the checks' findings. A failure writes the reason instead (Diagnostics shows it as Failed) and exits with
    code 2. The findings are also kept as restore-check-<time>.json in the backup set (or the work folder).
    The scratch database and work folder are removed afterwards unless -KeepRestored.

    Run it as an account that can restore databases on -SqlInstance (dbcreator, or sysadmin), read the backup, and
    write the status file. On a recovery server without the signing certificate, give -PublicKeys: a folder of the
    signing keys' public halves (casebook-keytool signing-public-key).

.EXAMPLE
    .\Test-CaseBookRestore.ps1 -Destination \\backup01\casebook
.EXAMPLE
    .\Test-CaseBookRestore.ps1 -RestoredDatabase CaseBook_Mounted -SqlInstance SQLREC01 -EvidencePath R:\evidence-store -KeysPath R:\keys
.EXAMPLE
    .\Test-CaseBookRestore.ps1 -Destination \\backup01\casebook -Register -At 03:00
#>
[CmdletBinding(DefaultParameterSetName = 'Set')]
param(
    [string] $SitePath = 'C:\inetpub\casebook',
    [Parameter(ParameterSetName = 'Set')] [string] $Destination,
    [Parameter(ParameterSetName = 'Set')] [string] $BackupSet,
    [Parameter(ParameterSetName = 'Set')] [string] $ScratchDatabase = 'CaseBook_RestoreDrill',
    [Parameter(ParameterSetName = 'Restored', Mandatory)] [string] $RestoredDatabase,
    [Parameter(ParameterSetName = 'Restored', Mandatory)] [string] $EvidencePath,
    [Parameter(ParameterSetName = 'Restored', Mandatory)] [string] $KeysPath,
    [string] $SqlInstance,
    [string] $WorkFolder,
    [int] $Sample = 200,
    [switch] $HashAll,
    [string] $PublicKeys,
    [string] $PfxPath,
    [string] $CertThumbprint,
    [switch] $KeepRestored,
    [switch] $Register,
    [string] $TaskAccount = 'SYSTEM',
    # SQL Server sign-in, where Windows authentication isn't possible (asked for with Get-Credential; never stored).
    [System.Management.Automation.PSCredential] $SqlCredential,
    [string] $At = '03:00'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\CaseBookSql.ps1')
. (Join-Path $PSScriptRoot 'lib\CaseBookStamp.ps1')
. (Join-Path $PSScriptRoot 'lib\CaseBookBackup.ps1')

if ($Register) {
    if (-not $Destination) { throw 'A scheduled drill restores the newest backup set: give -Destination with -Register.' }
    $arguments = "-SitePath `"$SitePath`" -Destination `"$Destination`" -Sample $Sample" +
        $(if ($SqlInstance) { " -SqlInstance `"$SqlInstance`"" } else { '' }) + $(if ($PublicKeys) { " -PublicKeys `"$PublicKeys`"" } else { '' })
    # Every fourth Sunday (about monthly).
    $trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Sunday -At $At
    Register-CaseBookTask -Name 'monthly restore drill' -Script $MyInvocation.MyCommand.Path -Arguments $arguments -Trigger $trigger -Account $TaskAccount
    return
}

$keytool = Join-Path $PSScriptRoot 'keytool\casebook-keytool.exe'
if (-not (Test-Path $keytool)) { throw "casebook-keytool isn't at $keytool. Run this from the deploy folder of a CaseBook release." }
$site = Read-CaseBookSite $SitePath
$statusFile = Get-CaseBookPath $site 'BackupStatus:FilePath'
if (-not $statusFile) { Write-Warning 'BackupStatus:FilePath isn''t set, so Diagnostics won''t see this drill. Set it in appsettings.Production.json.' }
$live = Get-CaseBookDatabase $site
if (-not $SqlInstance) { $SqlInstance = $live.Instance }
$stamp = Get-CaseBookStamp -Format 'yyyyMMdd-HHmm'
if (-not $WorkFolder) { $WorkFolder = Join-Path $env:TEMP "casebook-restore-drill-$stamp" }
$restoredHere = $false
$database = $null
$from = $null
$reportPath = Join-Path $WorkFolder 'restore-check.json'

try {
    New-Item -ItemType Directory -Force -Path $WorkFolder | Out-Null
    if ($PSCmdlet.ParameterSetName -eq 'Set') {
        if (-not $BackupSet) {
            if (-not $Destination) { throw 'Give -Destination (the newest backup set there is used) or -BackupSet.' }
            $BackupSet = @(Get-ChildItem -Path $Destination -Directory -Filter 'CaseBook-*' |
                Where-Object { Test-Path (Join-Path $_.FullName 'backup-set.json') } | Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName)[0]
            if (-not $BackupSet) { throw "No complete backup set (a CaseBook-* folder with backup-set.json) in $Destination." }
        }
        $manifest = Get-Content (Join-Path $BackupSet 'backup-set.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $from = Split-Path -Leaf $BackupSet
        if ($ScratchDatabase -eq $live.Name -and $SqlInstance -eq $live.Instance) { throw "The scratch database can't be the live one ($($live.Name))." }
        Write-Host "Restoring $from into $ScratchDatabase on $SqlInstance" -ForegroundColor Cyan

        $conn = New-CaseBookSqlConnection -SqlInstance $SqlInstance -DbName 'master' -SqlCredential $SqlCredential
        try {
            $exists = Invoke-CaseBookSqlScalar -Connection $conn -Sql 'SELECT COUNT(*) FROM sys.databases WHERE name = @n' -Parameters @{ '@n' = $ScratchDatabase }
            if ([int]$exists -gt 0) {
                Write-Host "  Removing the scratch database left by an earlier drill." -ForegroundColor Gray
                $null = Invoke-CaseBookSqlQuery -Connection $conn -Sql "ALTER DATABASE $(Get-SqlName $ScratchDatabase) SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE $(Get-SqlName $ScratchDatabase);"
            }
            $bak = $manifest.database.file
            $files = Invoke-CaseBookSqlQuery -Connection $conn -Sql 'RESTORE FILELISTONLY FROM DISK = @bak' -Parameters @{ '@bak' = $bak }
            $dataDir = "$(Invoke-CaseBookSqlScalar -Connection $conn -Sql "SELECT CAST(SERVERPROPERTY('InstanceDefaultDataPath') AS nvarchar(260))")"
            $logDir = "$(Invoke-CaseBookSqlScalar -Connection $conn -Sql "SELECT CAST(SERVERPROPERTY('InstanceDefaultLogPath') AS nvarchar(260))")"
            $moves = @(); $params = @{ '@bak' = $bak }; $i = 0
            foreach ($f in $files) {
                $dir = if ($f.Type -eq 'L') { $logDir } else { $dataDir }
                $sep = if ($dir.Contains('/')) { '/' } else { '\' }
                $ext = [System.IO.Path]::GetExtension("$($f.PhysicalName)")
                $params["@l$i"] = $f.LogicalName
                $params["@p$i"] = $dir.TrimEnd('\', '/') + $sep + "$ScratchDatabase-$($f.LogicalName)$ext"
                $moves += "MOVE @l$i TO @p$i"; $i++
            }
            $null = Invoke-CaseBookSqlQuery -Connection $conn -Parameters $params -Sql (
                "RESTORE DATABASE $(Get-SqlName $ScratchDatabase) FROM DISK = @bak WITH CHECKSUM, RECOVERY, " + ($moves -join ', '))
            $restoredHere = $true
        } finally { $conn.Dispose() }
        $database = $ScratchDatabase
        $evidence = $manifest.evidence.mirror
        $keys = Join-Path $BackupSet 'files\keys'
    } else {
        $database = $RestoredDatabase
        $evidence = (Resolve-Path $EvidencePath).Path
        $keys = (Resolve-Path $KeysPath).Path
        $from = "$RestoredDatabase on $SqlInstance"
        Write-Host "Checking $from, restored by your backup product" -ForegroundColor Cyan
    }

    Write-Host "  DBCC CHECKDB" -ForegroundColor Gray
    $conn = New-CaseBookSqlConnection -SqlInstance $SqlInstance -DbName 'master' -SqlCredential $SqlCredential
    try { $null = Invoke-CaseBookSqlQuery -Connection $conn -Sql "DBCC CHECKDB($(Get-SqlName $database)) WITH NO_INFOMSGS, ALL_ERRORMSGS" }
    finally { $conn.Dispose() }

    # A site folder describing the copy: the live settings, pointed at the restored database, evidence and keys.
    $scratch = Join-Path $WorkFolder 'site'
    New-Item -ItemType Directory -Force -Path $scratch | Out-Null
    $settings = Get-Content (Join-Path $site.Folder 'appsettings.Production.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    function Set-Path($obj, [string] $path, $value) {
        $node = $obj; $parts = $path.Split(':')
        for ($j = 0; $j -lt $parts.Length - 1; $j++) {
            if (-not $node.PSObject.Properties[$parts[$j]]) { $node | Add-Member -NotePropertyName $parts[$j] -NotePropertyValue ([pscustomobject]@{}) }
            $node = $node.($parts[$j])
        }
        $node | Add-Member -NotePropertyName $parts[-1] -NotePropertyValue $value -Force
    }
    $b = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $b['Data Source'] = $SqlInstance; $b['Initial Catalog'] = $database
    if ($SqlCredential) {
        # Only in the work folder, which only this account can read, and which is removed afterwards.
        $b['User ID'] = $SqlCredential.UserName; $b['Password'] = $SqlCredential.GetNetworkCredential().Password
        & icacls $WorkFolder /inheritance:r /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):(OI)(CI)F" | Out-Null
    } else { $b['Integrated Security'] = $true }
    $b['Encrypt'] = $true; $b['TrustServerCertificate'] = $true; $b['Application Name'] = 'CaseBook restore drill'
    Set-Path $settings 'ConnectionStrings:Default' $b.ConnectionString
    Set-Path $settings 'Database:Provider' 'SqlServer'
    Set-Path $settings 'EvidenceStore:RootPath' $evidence
    $signingName = Split-Path -Leaf (Get-CaseBookPath $site 'Integrity:SigningKeyPath' 'App_Data/keys/seal-signing.pem')
    Set-Path $settings 'Integrity:SigningKeyPath' (Join-Path $keys $signingName)
    # Key folders kept outside the keys folder are in the set under their own names (Get-CaseBookBackupFolders).
    $retiredSeals = if ($BackupSet -and (Test-Path (Join-Path $BackupSet 'files\retired-seal-keys'))) { Join-Path $BackupSet 'files\retired-seal-keys' } else { Join-Path $keys 'retired' }
    $retiredChain = if ($BackupSet -and (Test-Path (Join-Path $BackupSet 'files\chain-retired'))) { Join-Path $BackupSet 'files\chain-retired' } else { Join-Path $keys 'chain-retired' }
    Set-Path $settings 'Integrity:RetiredPublicKeysPath' $retiredSeals
    Set-Path $settings 'Integrity:ChainKey:WrappedKeyPath' (Join-Path $keys 'chain-key.json')
    Set-Path $settings 'Integrity:ChainKey:RetiredWrappedKeysPath' $retiredChain
    Set-Path $settings 'Storage:Encryption:EnvelopePath' (Join-Path $keys 'evidence-key.json')
    $settings | ConvertTo-Json -Depth 32 | Set-Content -Path (Join-Path $scratch 'appsettings.Production.json') -Encoding UTF8

    $toolArgs = @('verify-restore', '--site', $scratch, '--out', $reportPath)
    if ($HashAll) { $toolArgs += '--hash-all' } else { $toolArgs += @('--sample', "$Sample") }
    if ($PublicKeys) { $toolArgs += @('--public-keys', $PublicKeys) }
    if ($PfxPath) { $toolArgs += @('--pfx', $PfxPath) }
    if ($CertThumbprint) { $toolArgs += @('--cert', $CertThumbprint, '--store', 'LocalMachine') }
    & $keytool @toolArgs
    $exit = $LASTEXITCODE
    if (-not (Test-Path $reportPath)) { throw "casebook-keytool verify-restore didn't write its findings (exit $exit)." }
    $report = Get-Content $reportPath -Raw -Encoding UTF8 | ConvertFrom-Json
    # The findings are kept: in the backup set, or beside the status file for a copy your backup product restored.
    $keptReport = if ($BackupSet) { Join-Path $BackupSet "restore-check-$stamp.json" }
                  elseif ($statusFile) { Join-Path (Split-Path -Parent $statusFile) "restore-check-$stamp.json" } else { $null }
    if ($keptReport) { Copy-Item $reportPath $keptReport -Force; Write-Host "  Findings: $keptReport" -ForegroundColor Gray }

    if ($exit -eq 0 -and $report.passed) {
        if ($statusFile) {
            Set-CaseBookBackupStatus -Path $statusFile -Values @{
                lastVerifiedRestoreUtc = Get-UtcStamp; lastVerifiedRestoreSet = $from; lastRestoreSummary = "DBCC CHECKDB: passed; $($report.summary)"
            }
        }
        Write-Host "Restore verified: $from." -ForegroundColor Green
    } else {
        $failed = @($report.checks | Where-Object { -not $_.passed } | ForEach-Object { "$($_.check): $($_.detail)" }) -join ' | '
        throw "A check failed on $from. $failed"
    }
}
catch {
    $reason = $_.Exception.Message
    Write-Host "Restore drill failed: $reason" -ForegroundColor Red
    if ($statusFile) {
        try { Set-CaseBookBackupStatus -Path $statusFile -Values @{ lastRestoreFailedUtc = Get-UtcStamp; lastRestoreError = $reason } }
        catch { Write-Warning "The failure couldn't be recorded in $statusFile either: $($_.Exception.Message)" }
    }
    $script:drillFailed = $true
}
finally {
    if (-not $KeepRestored) {
        if ($restoredHere) {
            try {
                $conn = New-CaseBookSqlConnection -SqlInstance $SqlInstance -DbName 'master' -SqlCredential $SqlCredential
                try { $null = Invoke-CaseBookSqlQuery -Connection $conn -Sql "ALTER DATABASE $(Get-SqlName $ScratchDatabase) SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE $(Get-SqlName $ScratchDatabase);" }
                finally { $conn.Dispose() }
            } catch { Write-Warning "The scratch database $ScratchDatabase couldn't be removed: $($_.Exception.Message)" }
        }
        if (Test-Path $WorkFolder) { Remove-Item -LiteralPath $WorkFolder -Recurse -Force -ErrorAction SilentlyContinue }
    } else {
        Write-Host "Kept: $(if ($restoredHere) { "the database $ScratchDatabase on $SqlInstance, and " })$WorkFolder" -ForegroundColor Yellow
    }
}
if ($script:drillFailed) { exit 2 }
exit 0
