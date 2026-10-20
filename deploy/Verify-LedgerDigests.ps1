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

    Exit code 0 when verified; 1 when the ledger doesn't match the digests (treat as possible tampering); 2 when the
    check couldn't run (SQL Server unreachable, sign-in or permission refused, a timeout, no digests): fix that and
    run it again. A run that couldn't complete proves nothing either way.

.PARAMETER ConfigFile
    Optional casebook.config.psd1; fills SqlInstance, DbName and LedgerDigestPath.

.PARAMETER DigestPath
    Folder holding the saved digests (casebook-ledger-*.json).

.PARAMETER Latest
    Verify against only the N most recent digests. Default: all of them.

.PARAMETER SqlCredential
    Only where Windows integrated authentication isn't available. Never stored.

.PARAMETER Register
    Creates (or replaces) the scheduled task "CaseBook ledger verify", every fourth Sunday at -At, as -TaskAccount (default
    SYSTEM), with this run's SqlInstance, DbName, DigestPath and -Latest. Its last run result is the exit code above:
    alert on anything but 0. It runs the copy of this script kept beside -SitePath (<site>-deploy) when there is one.
#>
[CmdletBinding()]
param(
    [string] $ConfigFile,
    [string] $SqlInstance,
    [string] $DbName,
    [string] $DigestPath,
    [int] $Latest = 0,
    [System.Management.Automation.PSCredential] $SqlCredential,
    [switch] $Register,
    [string] $TaskAccount = 'SYSTEM',
    [string] $At = '04:00',
    # The site, only to find the deploy scripts kept beside it (<site>-deploy) for -Register.
    [string] $SitePath = 'C:\inetpub\casebook'
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDir 'lib\CaseBookSql.ps1')
. (Join-Path $scriptDir 'lib\CaseBookStamp.ps1')   # BUG-600: ConvertFrom-CaseBookStamp

try {
    $fromFile = Merge-CaseBookConfig -ConfigFile $ConfigFile -Bound $PSBoundParameters -Names @('SqlInstance', 'DbName', 'LedgerDigestPath')
    if ($fromFile.SqlInstance) { $SqlInstance = $fromFile.SqlInstance }
    if ($fromFile.DbName) { $DbName = $fromFile.DbName }
    if (-not $DigestPath -and $fromFile.LedgerDigestPath) { $DigestPath = $fromFile.LedgerDigestPath }
    if (-not $DbName) { $DbName = 'CaseBook' }
    if (-not $SqlInstance) { throw 'Missing SqlInstance.' }
    if (-not $DigestPath -or -not (Test-Path $DigestPath)) { throw "Digest folder not found: $DigestPath" }

    if ($Register) {
        # The task gets the values themselves, not -ConfigFile: the answers file stays with the release folder.
        . (Join-Path $scriptDir 'lib\CaseBookBackup.ps1')
        $arguments = "-SqlInstance `"$SqlInstance`" -DbName `"$DbName`" -DigestPath `"$DigestPath`" -SitePath `"$SitePath`"" + $(if ($Latest -gt 0) { " -Latest $Latest" } else { '' })
        Register-CaseBookTask -Name 'ledger verify' -Script $MyInvocation.MyCommand.Path -SitePath $SitePath -Arguments $arguments `
            -Trigger (New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Sunday -At $At) -Account $TaskAccount
        exit 0
    }

    # BUG-600: oldest to newest by the ledger block each digest covers, then by the stamp in its name, not by the name:
    # a name stamped in a server culture with another calendar (Thai 2569, Hijri 1448) sorted out of order.
    $files = @(Get-ChildItem -Path $DigestPath -Filter "casebook-ledger-$DbName-*.json" | ForEach-Object {
            $block = $null
            try { $block = [long](([System.IO.File]::ReadAllText($_.FullName) | ConvertFrom-Json).block_id) } catch { $block = $null }
            $stamp = $null
            if ($_.Name -match '-(\d{8}-\d{6})Z\.json$') { $stamp = ConvertFrom-CaseBookStamp $Matches[1] }
            [pscustomobject]@{ File = $_; Block = $block; Stamp = $stamp }
        } | Sort-Object @{ Expression = { if ($null -eq $_.Block) { [long]::MaxValue } else { $_.Block } } },
                        @{ Expression = { if ($null -eq $_.Stamp) { [datetime]::MaxValue } else { $_.Stamp } } },
                        @{ Expression = { $_.File.Name } } |
        ForEach-Object { $_.File })
    if ($Latest -gt 0) { $files = @($files | Select-Object -Last $Latest) }
    if ($files.Count -eq 0) { throw "No digests for [$DbName] in $DigestPath." }

    $digests = foreach ($f in $files) { [System.IO.File]::ReadAllText($f.FullName).Trim() }
    $json = '[' + ($digests -join ',') + ']'

    Write-Host "==> Verifying [$DbName] on [$SqlInstance] against $($files.Count) digest(s)" -ForegroundColor Cyan
    Write-Host "    Oldest: $($files[0].Name)" -ForegroundColor Gray
    Write-Host "    Newest: $($files[-1].Name)" -ForegroundColor Gray

    # BUG-251: connecting is outside the verification, so an unreachable server or a refused sign-in reads as "couldn't
    # verify", not as tampering.
    $conn = New-CaseBookSqlConnection -SqlInstance $SqlInstance -DbName $DbName -SqlCredential $SqlCredential
    try {
        [void](Invoke-CaseBookSqlScalar -Connection $conn -Sql 'EXEC sys.sp_verify_database_ledger @digests' -Parameters @{ '@digests' = $json })
    } catch {
        # PowerShell wraps the SqlException (MethodInvocationException); unwrap it for SQL Server's details.
        $ex = $_.Exception
        while ($ex -and -not ($ex -is [System.Data.SqlClient.SqlException])) { $ex = $ex.InnerException }
        if (-not $ex) { throw }
        # Ledger verification reports a mismatch with its own errors (37xxx). Anything else (permission denied, a
        # timeout, a dropped connection) means the check didn't finish.
        $ledgerErrors = @($ex.Errors | Where-Object { $_.Number -ge 37300 -and $_.Number -le 37499 })
        if ($ledgerErrors.Count -gt 0) {
            Write-Host '  [FAIL] Ledger verification FAILED. Treat as a possible tampering incident and preserve the database and digests.' -ForegroundColor Red
            foreach ($e in $ex.Errors) { Write-Host "         $($e.Number): $($e.Message)" -ForegroundColor Red }
            exit 1
        }
        Write-Host "  [FAIL] Couldn't complete the verification (this isn't a tamper finding): fix the cause and run it again." -ForegroundColor Yellow
        foreach ($e in $ex.Errors) { Write-Host "         $($e.Number): $($e.Message)" -ForegroundColor Yellow }
        exit 2
    } finally { $conn.Close() }

    Write-Host '  [ OK ] Ledger verified: no ledger row changed since the digests were taken.' -ForegroundColor Green
    exit 0
} catch {
    Write-Host "  [FAIL] Couldn't verify (this isn't a tamper finding): $($_.Exception.Message)" -ForegroundColor Yellow
    exit 2
}
