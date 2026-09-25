# Shared SQL helpers for the ledger scripts (E-10). Dot-source this file.
#
# Uses System.Data.SqlClient, which ships with Windows PowerShell 5.1 / .NET Framework, so the ledger
# scripts need neither the SqlServer module nor sqlcmd.exe. Windows integrated authentication by default;
# pass a PSCredential (Get-Credential) only where integrated auth isn't possible. Nothing is stored.
# ASCII only: Windows PowerShell 5.1 misreads non-ASCII in BOM-less files.

function New-CaseBookSqlConnection {
    param(
        [Parameter(Mandatory)] [string] $SqlInstance,
        [Parameter(Mandatory)] [string] $DbName,
        [System.Management.Automation.PSCredential] $SqlCredential
    )
    $b = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $b['Data Source'] = $SqlInstance
    $b['Initial Catalog'] = $DbName
    $b['Encrypt'] = $true
    $b['TrustServerCertificate'] = $true
    $b['Application Name'] = 'CaseBook deploy'
    if ($SqlCredential) {
        $b['User ID'] = $SqlCredential.UserName
        $b['Password'] = $SqlCredential.GetNetworkCredential().Password
    } else {
        $b['Integrated Security'] = $true
    }
    $conn = New-Object System.Data.SqlClient.SqlConnection $b.ConnectionString
    # Surface PRINT output as it arrives (minus sp_rename's standard caution, which is expected here).
    $conn.add_InfoMessage({ param($s, $e) foreach ($m in $e.Errors) { if ($m.Class -le 10 -and $m.Message -notlike 'Caution: Changing any part of an object name*') { Write-Host "    $($m.Message)" -ForegroundColor Gray } } })
    $conn.Open()
    return $conn
}

# Runs a sqlcmd-style script: splits on lines that are just GO and skips ":" sqlcmd directives
# (":on error exit" is the default behaviour here anyway: the first error throws).
function Invoke-CaseBookSqlScript {
    param(
        [Parameter(Mandatory)] [System.Data.SqlClient.SqlConnection] $Connection,
        [Parameter(Mandatory)] [string] $Path
    )
    $batch = New-Object System.Text.StringBuilder
    $lines = Get-Content -Path $Path -Encoding UTF8
    $batches = @()
    foreach ($line in $lines) {
        if ($line -match '^\s*GO\s*$') { $batches += $batch.ToString(); [void]$batch.Clear(); continue }
        if ($line -match '^\s*:') { continue }
        [void]$batch.AppendLine($line)
    }
    if ($batch.ToString().Trim()) { $batches += $batch.ToString() }

    $results = @()
    foreach ($sql in $batches) {
        if (-not $sql.Trim()) { continue }
        $cmd = $Connection.CreateCommand()
        $cmd.CommandText = $sql
        $cmd.CommandTimeout = 0
        $reader = $cmd.ExecuteReader()
        try {
            do {
                while ($reader.Read()) {
                    $row = [ordered]@{}
                    for ($i = 0; $i -lt $reader.FieldCount; $i++) { $row[$reader.GetName($i)] = $reader.GetValue($i) }
                    $results += [pscustomobject]$row
                }
            } while ($reader.NextResult())
        } finally { $reader.Close() }
    }
    return $results
}

function Invoke-CaseBookSqlScalar {
    param(
        [Parameter(Mandatory)] [System.Data.SqlClient.SqlConnection] $Connection,
        [Parameter(Mandatory)] [string] $Sql,
        [hashtable] $Parameters = @{}
    )
    $cmd = $Connection.CreateCommand()
    $cmd.CommandText = $Sql
    $cmd.CommandTimeout = 0
    foreach ($k in $Parameters.Keys) { [void]$cmd.Parameters.AddWithValue($k, $Parameters[$k]) }
    return $cmd.ExecuteScalar()
}

# Reads SqlInstance / DbName from a casebook.config.psd1 answers file when not passed explicitly.
function Merge-CaseBookConfig {
    param([string] $ConfigFile, [hashtable] $Bound, [string[]] $Names)
    $out = @{}
    if ($ConfigFile) {
        if (-not (Test-Path $ConfigFile)) { throw "Config file not found: $ConfigFile" }
        $cfg = Import-PowerShellDataFile -Path $ConfigFile
        foreach ($n in $Names) {
            if (-not $Bound.ContainsKey($n) -and $cfg.ContainsKey($n) -and "$($cfg[$n])" -ne '') { $out[$n] = $cfg[$n] }
        }
    }
    return $out
}
