#Requires -Version 5.1
<#
.SYNOPSIS
    Saves a SQL Server ledger digest for the CaseBook database to a folder (E-10).

.DESCRIPTION
    Calls sys.sp_generate_database_ledger_digest and writes the JSON result to
    <DigestPath>\casebook-ledger-<db>-<yyyyMMdd-HHmmss>Z.json.

    A digest is a hash over every ledger transaction so far. Kept somewhere the DBA can't alter
    (an immutable/WORM share, or a separate security-owned server), a series of digests lets
    Verify-LedgerDigests.ps1 prove later that no ledger row was changed, even by a sysadmin or by
    editing the database files directly.

    Schedule it daily (and after major events). Example, as an account with GENERATE LEDGER DIGEST
    (db_owner has it) and write access to the share:

      schtasks /Create /TN "CaseBook ledger digest" /SC DAILY /ST 02:00 /RU "CONTOSO\svc-casebook-ops" /RP `
        /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\CaseBook\deploy\Export-LedgerDigest.ps1 -ConfigFile C:\CaseBook\deploy\casebook.config.psd1"

    Exit code 0 on success, 1 on failure, so the scheduler can alert.

.PARAMETER ConfigFile
    Optional casebook.config.psd1; fills SqlInstance, DbName and LedgerDigestPath.

.PARAMETER DigestPath
    Destination folder. Created if missing.

.PARAMETER SqlCredential
    Only where Windows integrated authentication isn't available. Never stored.
#>
[CmdletBinding()]
param(
    [string] $ConfigFile,
    [string] $SqlInstance,
    [string] $DbName,
    [string] $DigestPath,
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
    if (-not $DigestPath) { throw 'Missing DigestPath (or LedgerDigestPath in the config file).' }

    if (-not (Test-Path $DigestPath)) { New-Item -ItemType Directory -Path $DigestPath | Out-Null }

    $conn = New-CaseBookSqlConnection -SqlInstance $SqlInstance -DbName $DbName -SqlCredential $SqlCredential
    try {
        $digest = Invoke-CaseBookSqlScalar -Connection $conn -Sql 'EXEC sys.sp_generate_database_ledger_digest'
    } finally { $conn.Close() }
    if (-not $digest -or $digest -is [DBNull]) { throw 'SQL Server returned no digest. Is the ledger enabled (Enable-Ledger.ps1)?' }

    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $file = Join-Path $DigestPath ("casebook-ledger-{0}-{1}Z.json" -f $DbName, $stamp)
    # ASCII: the digest is plain JSON, and this keeps the file byte-identical across PowerShell versions.
    [System.IO.File]::WriteAllText($file, [string]$digest, [System.Text.Encoding]::ASCII)
    Write-Host "  [ OK ] Ledger digest saved: $file" -ForegroundColor Green
    exit 0
} catch {
    Write-Host "  [FAIL] Ledger digest not saved: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
