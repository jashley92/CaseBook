# Shared helpers for the backup and restore-drill scripts (Backup-CaseBook.ps1, Update-CaseBookBackupStatus.ps1,
# Test-CaseBookRestore.ps1). Dot-source this file after lib\CaseBookSql.ps1.
# ASCII only: Windows PowerShell 5.1 misreads non-ASCII in BOM-less files.

# The site's settings as the app reads them: appsettings.json, then appsettings.Production.json over it.
function Read-CaseBookSite {
    param([Parameter(Mandatory)] [string] $SitePath)
    $site = (Resolve-Path $SitePath).Path
    $prod = Join-Path $site 'appsettings.Production.json'
    if (-not (Test-Path $prod)) { throw "appsettings.Production.json isn't in $site. Give -SitePath, the CaseBook site folder." }
    $base = Join-Path $site 'appsettings.json'
    $layers = @()
    if (Test-Path $base) { $layers += (Get-Content $base -Raw -Encoding UTF8 | ConvertFrom-Json) }
    $layers += (Get-Content $prod -Raw -Encoding UTF8 | ConvertFrom-Json)
    return [pscustomobject]@{ Folder = $site; Layers = $layers }
}

# One setting by its path ('Integrity:SigningKeyPath'): the last layer that sets it wins, as in the app.
function Get-CaseBookSetting {
    param([Parameter(Mandatory)] $Site, [Parameter(Mandatory)] [string] $Path)
    $found = $null
    foreach ($layer in $Site.Layers) {
        $node = $layer
        foreach ($part in $Path.Split(':')) {
            if ($null -eq $node -or $node -isnot [System.Management.Automation.PSCustomObject] -or -not $node.PSObject.Properties[$part]) { $node = $null; break }
            $node = $node.$part
        }
        if ($null -ne $node -and "$node" -ne '') { $found = $node }
    }
    return $found
}

# A path setting resolved as the app resolves it (against the site folder), or $null when it isn't set.
function Get-CaseBookPath {
    param([Parameter(Mandatory)] $Site, [Parameter(Mandatory)] [string] $Path, [string] $Default)
    $p = Get-CaseBookSetting $Site $Path
    if (-not $p) { $p = $Default }
    if (-not $p) { return $null }
    if ([System.IO.Path]::IsPathRooted($p)) { return [System.IO.Path]::GetFullPath($p) }
    return [System.IO.Path]::GetFullPath((Join-Path $Site.Folder $p))
}

# The SQL Server instance and database the site's connection string names.
function Get-CaseBookDatabase {
    param([Parameter(Mandatory)] $Site)
    $provider = Get-CaseBookSetting $Site 'Database:Provider'
    if ("$provider" -ne 'SqlServer') { throw "The site's database isn't SQL Server (Database:Provider is '$provider'); these scripts back up SQL Server." }
    $cs = Get-CaseBookSetting $Site 'ConnectionStrings:Default'
    if (-not $cs) { throw 'The site has no ConnectionStrings:Default.' }
    $b = New-Object System.Data.SqlClient.SqlConnectionStringBuilder $cs
    return [pscustomobject]@{ Instance = $b.DataSource; Name = $b.InitialCatalog }
}

# The folders a backup set holds besides the database (OPERATIONS.md section 1, Administration > Diagnostics > Backup set).
# Label is the folder's name inside a backup set. Evidence is listed apart: it's large and only ever grows, so it's kept
# in one mirror the sets share.
function Get-CaseBookBackupFolders {
    param([Parameter(Mandatory)] $Site)
    $signing = Get-CaseBookPath $Site 'Integrity:SigningKeyPath' 'App_Data/keys/seal-signing.pem'
    $keys = Split-Path -Parent $signing
    $list = @(
        [pscustomobject]@{ Label = 'keys';             Key = 'Integrity:SigningKeyPath (its folder)'; Path = $keys }
        [pscustomobject]@{ Label = 'dp-keys';          Key = 'DataProtection:KeyPath';   Path = (Get-CaseBookPath $Site 'DataProtection:KeyPath') }
        [pscustomobject]@{ Label = 'seals';            Key = 'Integrity:ExportPath';     Path = (Get-CaseBookPath $Site 'Integrity:ExportPath' 'seals') }
        [pscustomobject]@{ Label = 'report-output';    Key = 'ReportOutput:RootPath';    Path = (Get-CaseBookPath $Site 'ReportOutput:RootPath') }
        [pscustomobject]@{ Label = 'branding';         Key = 'ReportBranding:RootPath';  Path = (Get-CaseBookPath $Site 'ReportBranding:RootPath') }
        [pscustomobject]@{ Label = 'report-templates'; Key = 'ReportTemplates:RootPath'; Path = (Get-CaseBookPath $Site 'ReportTemplates:RootPath') }
    )
    # Key files set outside the keys folder go too (the chain key's, the retired keys', the evidence key's envelope).
    foreach ($k in @(
        @{ Label = 'chain-retired';  Key = 'Integrity:ChainKey:RetiredWrappedKeysPath'; Path = (Get-CaseBookPath $Site 'Integrity:ChainKey:RetiredWrappedKeysPath') }
        @{ Label = 'retired-seal-keys'; Key = 'Integrity:RetiredPublicKeysPath'; Path = (Get-CaseBookPath $Site 'Integrity:RetiredPublicKeysPath') })) {
        if ($k.Path -and -not $k.Path.StartsWith($keys, [StringComparison]::OrdinalIgnoreCase)) { $list += [pscustomobject]$k }
    }
    return @($list | Where-Object { $_.Path })
}

function Get-CaseBookEvidenceFolder {
    param([Parameter(Mandatory)] $Site)
    return Get-CaseBookPath $Site 'EvidenceStore:RootPath' 'App_Data/evidence-store'
}

# Merges values into the status file the app reads (BackupStatus:FilePath), keeping what's there; written to a temporary
# file and moved over, so the app never reads half a file.
function Set-CaseBookBackupStatus {
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [hashtable] $Values)
    $status = [pscustomobject]@{}
    if (Test-Path $Path) {
        try { $status = Get-Content $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $status = [pscustomobject]@{} }
    }
    foreach ($k in $Values.Keys) { $status | Add-Member -NotePropertyName $k -NotePropertyValue $Values[$k] -Force }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $tmp = "$Path.tmp"
    $status | ConvertTo-Json -Depth 5 | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $Path -Force
}

# BUG-600: in the invariant culture (lib\CaseBookStamp.ps1), whatever the server's calendar.
function Get-UtcStamp([datetime] $When = [datetime]::Now) { return Get-CaseBookStamp -Format 'yyyy-MM-ddTHH:mm:ssZ' -Utc -When $When }

# A query's rows, with parameters, no time limit (backups and restores take as long as they take).
function Invoke-CaseBookSqlQuery {
    param(
        [Parameter(Mandatory)] [System.Data.SqlClient.SqlConnection] $Connection,
        [Parameter(Mandatory)] [string] $Sql,
        [hashtable] $Parameters = @{}
    )
    $cmd = $Connection.CreateCommand()
    $cmd.CommandText = $Sql
    $cmd.CommandTimeout = 0
    foreach ($k in $Parameters.Keys) { [void]$cmd.Parameters.AddWithValue($k, $Parameters[$k]) }
    $reader = $cmd.ExecuteReader()
    $rows = @()
    try {
        do {
            while ($reader.Read()) {
                $row = [ordered]@{}
                for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                    $v = $reader.GetValue($i)
                    $row[$reader.GetName($i)] = if ($v -is [System.DBNull]) { $null } else { $v }
                }
                $rows += [pscustomobject]$row
            }
        } while ($reader.NextResult())
    } finally { $reader.Close() }
    return ,$rows
}

# A SQL Server identifier, bracketed and with any closing bracket doubled.
function Get-SqlName([string] $Name) { return '[' + $Name.Replace(']', ']]') + ']' }

# Copies a folder with robocopy; returns its file count and bytes. Robocopy's exit codes 0-7 are success.
function Copy-CaseBookFolder {
    param([Parameter(Mandatory)] [string] $From, [Parameter(Mandatory)] [string] $To, [string[]] $ExcludeDirs = @())
    New-Item -ItemType Directory -Force -Path $To | Out-Null
    $rcArgs = @($From, $To, '/E', '/COPY:DAT', '/DCOPY:T', '/R:2', '/W:5', '/NP', '/NFL', '/NDL', '/NJH', '/NJS')
    if ($ExcludeDirs.Count) { $rcArgs += "/XD"; $rcArgs += $ExcludeDirs }
    & robocopy @rcArgs | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Copying $From to $To failed (robocopy exit $LASTEXITCODE)." }
    $files = @(Get-ChildItem -Path $To -Recurse -File -Force -ErrorAction SilentlyContinue)
    return [pscustomobject]@{ Files = $files.Count; Bytes = [long](($files | Measure-Object -Property Length -Sum).Sum) }
}

# Registers (or replaces) a Windows scheduled task that runs a deploy script as the account given.
function Register-CaseBookTask {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Script,
        [Parameter(Mandatory)] [string] $Arguments,
        [Parameter(Mandatory)] $Trigger,
        [string] $Account = 'SYSTEM',
        # The site, to find the copy of the deploy scripts kept beside it (<site>-deploy), which upgrades keep current.
        [string] $SitePath
    )
    if ($SitePath) {
        $site = $SitePath.TrimEnd([char]92)
        $kept = Join-Path (Join-Path (Split-Path -Parent $site) "$(Split-Path -Leaf $site)-deploy") (Split-Path -Leaf $Script)
        if (Test-Path $kept) { $Script = $kept }
        else { Write-Warning "There's no $kept, so the task runs $Script. Move or delete this folder and the task fails: install or upgrade (which keeps the deploy scripts beside the site), then run -Register again." }
    }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Script`" $Arguments"
    $principal = if ($Account -eq 'SYSTEM') {
        New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    } else {
        # A group managed service account (DOMAIN\name$) needs no password; another account is asked for one.
        New-ScheduledTaskPrincipal -UserId $Account -LogonType Password -RunLevel Highest
    }
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 12) -MultipleInstances IgnoreNew
    $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $Trigger -Settings $settings `
        -Description "CaseBook: $Name (see OPERATIONS.md section 1)"
    if ($Account -ne 'SYSTEM' -and -not $Account.EndsWith('$')) {
        $cred = Get-Credential -UserName $Account -Message "Password for $Account, to run the scheduled task"
        Register-ScheduledTask -TaskName "CaseBook $Name" -InputObject $task -User $Account -Password $cred.GetNetworkCredential().Password -Force | Out-Null
    } else {
        Register-ScheduledTask -TaskName "CaseBook $Name" -InputObject $task -Force | Out-Null
    }
    Write-Host "Registered the scheduled task 'CaseBook $Name', running $Script as $Account." -ForegroundColor Green
}
