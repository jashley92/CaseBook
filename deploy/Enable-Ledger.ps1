#Requires -Version 5.1
<#
.SYNOPSIS
    Turns on the SQL Server 2022 ledger for CaseBook's evidentiary tables (E-10). One-way.

.DESCRIPTION
    Runs deploy/sql/02-Enable-Ledger.sql against the CaseBook database. It rebuilds AuditLog,
    IntegritySeals and ChainOfCustodyEvents as APPEND-ONLY LEDGER tables, keeping every existing
    row, so SQL Server itself refuses UPDATE, DELETE and TRUNCATE on them for every principal
    (including db_owner and sysadmin) and records a cryptographic digest of each insert.

    Then it writes the first ledger digest to -DigestPath (see Export-LedgerDigest.ps1). Schedule
    Export-LedgerDigest.ps1 daily and run Verify-LedgerDigests.ps1 to prove the tables are unchanged.

    Run once per database, after the schema exists (after the app's first start), as sysadmin or
    db_owner. Stop the CaseBook app pool first: the conversion renames and rebuilds the tables.
    Idempotent: tables that are already ledger tables are left alone.

    THIS CANNOT BE UNDONE. A ledger table can't be turned back into an ordinary table. The script
    refuses to run unless the database has a FULL backup from the last 24 hours (override with
    -SkipBackupCheck only on a throwaway database).

.PARAMETER ConfigFile
    Optional casebook.config.psd1 answers file; fills SqlInstance, DbName and LedgerDigestPath.

.PARAMETER SqlInstance
    Target instance, e.g. "SQLHOST" or "SQLHOST\INSTANCE".

.PARAMETER DbName
    Database name. Default: CaseBook.

.PARAMETER DigestPath
    Folder for ledger digests, ideally an immutable (WORM) share the DBA can't modify. The first
    digest is written here. Optional, but you need it to verify later.

.PARAMETER SqlCredential
    Only where Windows integrated authentication isn't available (e.g. a lab container). Prompted
    with Get-Credential; never stored.

.PARAMETER SkipBackupCheck
    Skip the recent-full-backup safety check. Throwaway databases only.

.EXAMPLE
    .\Enable-Ledger.ps1 -ConfigFile .\casebook.config.psd1

.EXAMPLE
    .\Enable-Ledger.ps1 -SqlInstance SQLHOST\PROD -DigestPath \\worm01\casebook-ledger
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $ConfigFile,
    [string] $SqlInstance,
    [string] $DbName,
    [string] $DigestPath,
    [System.Management.Automation.PSCredential] $SqlCredential,
    [switch] $SkipBackupCheck
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDir 'lib\CaseBookSql.ps1')

$fromFile = Merge-CaseBookConfig -ConfigFile $ConfigFile -Bound $PSBoundParameters -Names @('SqlInstance', 'DbName', 'LedgerDigestPath')
if ($fromFile.SqlInstance) { $SqlInstance = $fromFile.SqlInstance }
if ($fromFile.DbName) { $DbName = $fromFile.DbName }
if (-not $DigestPath -and $fromFile.LedgerDigestPath) { $DigestPath = $fromFile.LedgerDigestPath }
if (-not $DbName) { $DbName = 'CaseBook' }
if (-not $SqlInstance) { throw 'Missing SqlInstance. Pass -SqlInstance or set it in -ConfigFile.' }

$sqlFile = Join-Path $scriptDir 'sql\02-Enable-Ledger.sql'
if (-not (Test-Path $sqlFile)) { throw "Missing $sqlFile" }

Write-Host "==> Ledger for [$DbName] on [$SqlInstance]" -ForegroundColor Cyan
$conn = New-CaseBookSqlConnection -SqlInstance $SqlInstance -DbName $DbName -SqlCredential $SqlCredential
try {
    if (-not $SkipBackupCheck) {
        $lastFull = Invoke-CaseBookSqlScalar -Connection $conn -Sql @"
SELECT MAX(backup_finish_date) FROM msdb.dbo.backupset WHERE database_name = @db AND type = 'D'
"@ -Parameters @{ '@db' = $DbName }
        if ($lastFull -is [DBNull] -or $null -eq $lastFull -or $lastFull -lt (Get-Date).AddHours(-24)) {
            throw "No full backup of [$DbName] in the last 24 hours. Take one first: enabling the ledger can't be undone."
        }
        Write-Host "    Last full backup: $lastFull" -ForegroundColor Gray
    }

    if (-not $PSCmdlet.ShouldProcess("[$DbName] on [$SqlInstance]", 'Convert AuditLog, IntegritySeals and ChainOfCustodyEvents to append-only ledger tables (irreversible)')) {
        return
    }

    $summary = Invoke-CaseBookSqlScript -Connection $conn -Path $sqlFile
    $summary | Format-Table -AutoSize | Out-String | Write-Host

    $notLedger = @($summary | Where-Object { $_.Ledger -ne 'APPEND_ONLY_LEDGER_TABLE' })
    if ($notLedger.Count -gt 0 -or $summary.Count -lt 3) { throw 'Not every table reports APPEND_ONLY_LEDGER_TABLE. See the output above.' }

    if ($DigestPath) {
        & (Join-Path $scriptDir 'Export-LedgerDigest.ps1') -SqlInstance $SqlInstance -DbName $DbName -DigestPath $DigestPath -SqlCredential $SqlCredential
    } else {
        Write-Host '    No -DigestPath given. Run Export-LedgerDigest.ps1 now and on a schedule; without digests the ledger can''t be verified.' -ForegroundColor Yellow
    }
} finally {
    $conn.Close()
}
Write-Host '==> Ledger enabled.' -ForegroundColor Green
