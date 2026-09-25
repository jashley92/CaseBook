#Requires -Version 5.1
<#
.SYNOPSIS
    Verifies the CaseBook ledger tables against saved digests (E-10).

.DESCRIPTION
    Reads the digests Export-LedgerDigest.ps1 saved in -DigestPath and runs
    sys.sp_verify_database_ledger with all of them. SQL Server recomputes the hashes of every ledger
    row and transaction and checks them against the digests. Any row changed after a digest was taken,
    by any means (including a sysadmin or a direct edit of the database files), fails verification.

    Run it monthly, before an examination, and whenever the audit chain check in the app fails. Keep the
    output with your NYDFS 500 evidence.

    Exit code 0 when verified, 1 when verification fails or can't run.

.PARAMETER ConfigFile
    Optional casebook.config.psd1; fills SqlInstance, DbName and LedgerDigestPath.

.PARAMETER DigestPath
    Folder holding the saved digests (casebook-ledger-*.json).

.PARAMETER Latest
    Verify against only the N most recent digests. Default: all of them.

.PARAMETER SqlCredential
    Only where Windows integrated authentication isn't available. Never stored.
#>
[CmdletBinding()]
param(
    [string] $ConfigFile,
    [string] $SqlInstance,
    [string] $DbName,
    [string] $DigestPath,
    [int] $Latest = 0,
    [System.Management.Automation.PSCredential] $SqlCredential
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDir 'lib\CaseBookSql.ps1')

try {
    $fromFile = Merge-CaseBookConfig -ConfigFile $ConfigFile -Bound $PSBoundParameters -Names @('SqlInstance', 'DbName', 'LedgerDigestPath')
    if ($fromFile.SqlInstance) { $SqlInstance = $fromFile.SqlInstance }
    if ($fromFile.DbName) { $DbName = $fromFile.DbName }
    if (-not $DigestPath -and $fromFile.LedgerDigestPath) { $DigestPath = $fromFile.LedgerDigestPath }
    if (-not $DbName) { $DbName = 'CaseBook' }
    if (-not $SqlInstance) { throw 'Missing SqlInstance.' }
    if (-not $DigestPath -or -not (Test-Path $DigestPath)) { throw "Digest folder not found: $DigestPath" }

    $files = @(Get-ChildItem -Path $DigestPath -Filter "casebook-ledger-$DbName-*.json" | Sort-Object Name)
    if ($Latest -gt 0) { $files = @($files | Select-Object -Last $Latest) }
    if ($files.Count -eq 0) { throw "No digests for [$DbName] in $DigestPath." }

    $digests = foreach ($f in $files) { [System.IO.File]::ReadAllText($f.FullName).Trim() }
    $json = '[' + ($digests -join ',') + ']'

    Write-Host "==> Verifying [$DbName] on [$SqlInstance] against $($files.Count) digest(s)" -ForegroundColor Cyan
    Write-Host "    Oldest: $($files[0].Name)" -ForegroundColor Gray
    Write-Host "    Newest: $($files[-1].Name)" -ForegroundColor Gray

    $conn = New-CaseBookSqlConnection -SqlInstance $SqlInstance -DbName $DbName -SqlCredential $SqlCredential
    try {
        [void](Invoke-CaseBookSqlScalar -Connection $conn -Sql 'EXEC sys.sp_verify_database_ledger @digests' -Parameters @{ '@digests' = $json })
    } finally { $conn.Close() }

    Write-Host '  [ OK ] Ledger verified: no ledger row changed since the digests were taken.' -ForegroundColor Green
    exit 0
} catch [System.Data.SqlClient.SqlException] {
    Write-Host '  [FAIL] Ledger verification FAILED. Treat as a possible tampering incident and preserve the database and digests.' -ForegroundColor Red
    # PowerShell wraps the SqlException (MethodInvocationException); unwrap it for SQL Server's details.
    $ex = $_.Exception
    while ($ex -and -not ($ex -is [System.Data.SqlClient.SqlException])) { $ex = $ex.InnerException }
    if ($ex) { foreach ($e in $ex.Errors) { Write-Host "         $($e.Message)" -ForegroundColor Red } }
    else { Write-Host "         $($_.Exception.Message)" -ForegroundColor Red }
    exit 1
} catch {
    Write-Host "  [FAIL] Couldn't verify: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
