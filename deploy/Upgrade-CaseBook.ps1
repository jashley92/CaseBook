#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    In-place upgrade of an existing CaseBook IIS deployment to a newer build.

.DESCRIPTION
    Safe, repeatable upgrade of a site that Install-CaseBook.ps1 (or an older version) stood up.
    Unlike re-running the installer, this never reconfigures IIS or changes an existing setting -- it
    swaps the app binaries and lets EF Core apply the pending migrations. The one exception: when a newer
    release added a data-folder setting (e.g. ReportTemplates:RootPath) that the deployed
    appsettings.Production.json lacks, it adds that setting under the data root (after backing the config
    up) and creates the folder, so the store doesn't fall back to App_Data in the read-only web root. It also snapshots the current binaries so a failed upgrade rolls back.

    Stages:
      1. Resolve the live deployment from IIS + the deployed appsettings.Production.json
         (SitePath, app pool, SQL instance/database, health URL).
      2. Preflight -- ASP.NET Core Module present, the .NET runtime major present, SQL reachable,
         and a MIGRATION-COMPATIBILITY check: compare the target DB's __EFMigrationsHistory with
         the release's migration manifest and STOP on a lineage mismatch (the state that makes the
         app fail on startup with "There is already an object named ..."). No blind migrate.
      3. Back up -- a server-side full DB backup, a copy of appsettings.Production.json, and a
         snapshot of the current site binaries (the rollback point).
      4. Deploy -- stop the app pool, mirror the new binaries into the site (preserving
         appsettings.Production.json and logs), start the pool.
      5. Migrate + warm -- the first request applies pending EF migrations; poll until the app
         responds. On failure, roll the binaries back automatically.

    Integrated auth throughout -- no secrets are read or written.

.PARAMETER BundleZip
    A release bundle produced by the Release workflow (casebook-<version>.zip: contains app/,
    migrations-sqlserver.txt, VERSION.txt). The recommended source -- no SDK needed on the server.

.PARAMETER Version
    A release to download from GitHub and upgrade to, e.g. v1.6.0, or 'latest' (PROD-50). The script downloads
    casebook-<version>.zip and its .sha256 from the repository's release, checks the hash, and continues as with
    -BundleZip. Needs outbound HTTPS to github.com (or -Proxy); a host without it downloads the bundle elsewhere and
    uses -BundleZip. Administration > Updates shows this command with the newest version filled in.

.PARAMETER Repository
    The GitHub repository releases are downloaded from with -Version (default 'jashley92/CaseBook').

.PARAMETER Proxy
    An outbound proxy for -Version (e.g. http://proxy.contoso.local:8080), used with your Windows credentials.

.PARAMETER AppSource
    A folder that already contains the published app (an extracted bundle's app\, or a build
    output) -- an alternative to -BundleZip.

.PARAMETER Build
    Build+publish from this repo instead of a bundle (requires the .NET 10 SDK on this host).

.PARAMETER SiteName
    IIS site name to upgrade (default 'CaseBook'). SitePath, app pool and the health URL are
    resolved from it unless overridden.

.PARAMETER SitePath / AppPoolName / SqlInstance / DbName / HealthUrl
    Overrides for the values otherwise auto-resolved from IIS and appsettings.Production.json.

.PARAMETER BackupRoot
    Where to write the config backup and the binary rollback snapshot (default:
    <SitePath>\..\casebook-upgrade-backups\<timestamp>). The DB backup is written server-side to
    the SQL instance's default backup directory.

.PARAMETER DataRoot
    The deployment's data root (evidence, reports, branding, keys ... outside the web root). Only needed when
    the preflight can't work it out from paths already in appsettings.Production.json and the config is
    missing a data-folder setting a newer release added.

.PARAMETER SkipDbBackup
    Skip the automatic DB backup (only if your backup is handled externally and is current).

.PARAMETER Force
    Do not prompt for confirmation before deploying.

.EXAMPLE
    .\Upgrade-CaseBook.ps1 -Version v2.4.0

.EXAMPLE
    .\Upgrade-CaseBook.ps1 -BundleZip .\casebook-v2.4.0.zip

.EXAMPLE
    .\Upgrade-CaseBook.ps1 -Build -SiteName CaseBook
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $BundleZip,
    [string] $Version,
    [string] $Repository = 'jashley92/CaseBook',
    [string] $Proxy,
    [string] $AppSource,
    [switch] $Build,

    [string] $SiteName = 'CaseBook',
    [string] $SitePath,
    [string] $AppPoolName,
    [string] $SqlInstance,
    [string] $DbName,
    [string] $HealthUrl,

    [string] $BackupRoot,
    [string] $DataRoot,
    [switch] $SkipDbBackup,
    [int]    $WarmupTimeoutSec = 660,   # WF-73: past the app's 600 s startupTimeLimit (web.config)
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
# REV-73: Windows PowerShell 5.1 offers only SSL3/TLS 1.0 by default unless the host sets SchUseStrongCrypto, and a host
# with those turned off then refuses every HTTPS probe below (a healthy site reads as down).
# (Left to the OS when it already decides: SystemDefault includes TLS 1.2 and 1.3.)
if ([Net.ServicePointManager]::SecurityProtocol -ne [Net.SecurityProtocolType]::SystemDefault) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Info($m) { Write-Host "    $m" -ForegroundColor Gray }
function Write-Warn2($m){ Write-Host "    $m" -ForegroundColor Yellow }

$sourceCount = @($BundleZip, $Version, $AppSource).Where({ $_ }).Count + [int][bool]$Build
if ($sourceCount -ne 1) { throw "Specify exactly one source: -Version <vX.Y.Z>, -BundleZip <zip>, -AppSource <folder>, or -Build." }

$deployDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $deployDir
$stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'

# --- 1. Resolve the live deployment from IIS + appsettings.Production.json -----
Write-Step "Resolving the '$SiteName' deployment"
Import-Module WebAdministration -ErrorAction Stop
. (Join-Path $deployDir 'lib\CaseBookIis.ps1')   # REV-72: Stop-CaseBookAppPool
$site = Get-Website -Name $SiteName -ErrorAction SilentlyContinue
if (-not $site) { throw "IIS site '$SiteName' not found. Pass -SiteName, or use Install-CaseBook.ps1 for a first install." }

if (-not $SitePath)    { $SitePath    = $site.physicalPath }
if (-not $AppPoolName) { $AppPoolName = $site.applicationPool }
if (-not (Test-Path $SitePath)) { throw "Site physical path not found: $SitePath" }

$prodSettings = Join-Path $SitePath 'appsettings.Production.json'
if (-not (Test-Path $prodSettings)) { throw "appsettings.Production.json not found in $SitePath -- is this a CaseBook site?" }

# Read SQL instance/database straight from the connection string the app uses (key 'Default').
if (-not $SqlInstance -or -not $DbName) {
    try {
        $cfg = Get-Content $prodSettings -Raw | ConvertFrom-Json
        $connStr = $cfg.ConnectionStrings.Default
        $csb = New-Object System.Data.SqlClient.SqlConnectionStringBuilder($connStr)
        if (-not $SqlInstance) { $SqlInstance = $csb.DataSource }
        if (-not $DbName)      { $DbName      = $csb.InitialCatalog }
    } catch { throw "Could not parse the SQL connection string from $prodSettings ($($_.Exception.Message))." }
}
# A dedicated connection string for our own preflight/backup work (Windows auth, tolerant of a self-signed cert).
$adminConn = "Server=$SqlInstance;Database=$DbName;Trusted_Connection=True;Encrypt=False;TrustServerCertificate=True;Application Name=CaseBook-Upgrade;"

# BUG-138: a binding is "IP:port:host"; a site on a port other than the scheme's default is probed on that port.
function Get-BindingUrl($binding, $scheme, $defaultPort) {
    $parts = $binding.bindingInformation -split ':'
    $hostHeader = if ($parts[-1]) { $parts[-1] } else { 'localhost' }
    $port = if ($parts.Length -ge 3) { $parts[-2] } else { '' }
    $portPart = if ($port -and $port -ne "$defaultPort") { ":$port" } else { '' }
    return "${scheme}://$hostHeader$portPart/"
}
if (-not $HealthUrl) {
    $https = Get-WebBinding -Name $SiteName -Protocol https -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($https) {
        $HealthUrl = Get-BindingUrl $https 'https' 443
    } else {
        $http = Get-WebBinding -Name $SiteName -Protocol http -ErrorAction SilentlyContinue | Select-Object -First 1
        $HealthUrl = if ($http) { Get-BindingUrl $http 'http' 80 } else { 'http://localhost/' }
    }
}
Write-Info "Site path : $SitePath"
Write-Info "App pool  : $AppPoolName"
Write-Info "Database  : $DbName on $SqlInstance"
Write-Info "Health URL: $HealthUrl"
# BUG-249: the warm-up asks the app itself. Windows Auth answers anonymous requests to the site with 401 from IIS,
# before the app runs, so a 401 there didn't prove the new build started. /api is anonymous at the IIS level (the
# installer carves it out for API tokens) and the import schema is served by the app with no sign-in: a 200 from it
# means the app is up.
$siteBase = ([Uri]$HealthUrl).GetLeftPart([UriPartial]::Authority)
$ProbeUrl = "$siteBase/api/import/cases/schema"
Write-Info "Probe URL : $ProbeUrl"

# Small SQL helpers over System.Data.SqlClient (present in Windows PowerShell 5.1 -- no module needed).
function Invoke-SqlScalar([string]$query) {
    $c = New-Object System.Data.SqlClient.SqlConnection($adminConn)
    try { $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $query; return $cmd.ExecuteScalar() }
    finally { $c.Dispose() }
}
function Invoke-SqlColumn([string]$query) {
    $c = New-Object System.Data.SqlClient.SqlConnection($adminConn)
    try {
        $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $query
        $r = $cmd.ExecuteReader(); $out = New-Object System.Collections.Generic.List[string]
        while ($r.Read()) { $out.Add([string]$r.GetValue(0)) }
        # Return the items themselves (no leading comma): the caller collects them with @(), which yields an empty,
        # one- or many-element array. A ',' here wrapped the list in a second array, so every applied migration
        # read as unknown and the preflight reported a false MIGRATION MISMATCH.
        return $out.ToArray()
    } finally { $c.Dispose() }
}
function Invoke-SqlNonQuery([string]$query, [int]$timeoutSec = 0) {
    $c = New-Object System.Data.SqlClient.SqlConnection($adminConn)
    try { $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $query; $cmd.CommandTimeout = $timeoutSec; [void]$cmd.ExecuteNonQuery() }
    finally { $c.Dispose() }
}

# --- 2. Stage the new build (so the preflight can read its migration manifest) -
$staging = Join-Path $env:TEMP "casebook-upgrade-$stamp"
New-Item -ItemType Directory -Force -Path $staging | Out-Null
$appSrc = $null; $manifest = $null; $targetVersion = $null

# PROD-50: -Version downloads the release bundle and its .sha256 itself, as you, on this host, and refuses a bundle whose
# hash doesn't match. Nothing the web app wrote is used.
if ($Version) {
    if ($Repository -notmatch '^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$') { throw "-Repository must be owner/name, not '$Repository'." }
    $web = @{ UseBasicParsing = $true; TimeoutSec = 300 }
    if ($Proxy) { $web.Proxy = $Proxy; $web.ProxyUseDefaultCredentials = $true }
    $ProgressPreference = 'SilentlyContinue'   # Windows PowerShell's progress bar slows a download many times over
    if ($Version -ieq 'latest') {
        Write-Step "Finding the latest release of $Repository"
        $latest = Invoke-RestMethod @web -Uri "https://api.github.com/repos/$Repository/releases/latest" -Headers @{ 'User-Agent' = 'CaseBook-Upgrade' }
        $Version = [string]$latest.tag_name
    }
    if ($Version -notmatch '^v\d{1,4}\.\d{1,4}\.\d{1,4}$') { throw "-Version must be a release tag like v1.6.0 (or 'latest'), not '$Version'." }

    $download = Join-Path $env:TEMP "casebook-download-$stamp"
    New-Item -ItemType Directory -Force -Path $download | Out-Null
    $zipName = "casebook-$Version.zip"
    $base = "https://github.com/$Repository/releases/download/$Version"
    Write-Step "Downloading $zipName from $Repository"
    $BundleZip = Join-Path $download $zipName
    $shaFile = "$BundleZip.sha256"
    try {
        Invoke-WebRequest @web -Uri "$base/$zipName.sha256" -OutFile $shaFile
        Invoke-WebRequest @web -Uri "$base/$zipName" -OutFile $BundleZip
    } catch {
        throw ("Couldn't download $Version from github.com/$Repository ($($_.Exception.Message)). Check the version exists " +
               "and this host can reach github.com (or pass -Proxy); otherwise download the bundle elsewhere and use -BundleZip.")
    }
    $expected = ((Get-Content $shaFile -Raw).Trim() -split '\s+')[0]
    $actual = (Get-FileHash -Path $BundleZip -Algorithm SHA256).Hash
    if ($expected -notmatch '^[0-9a-fA-F]{64}$' -or $actual -ine $expected) {
        throw "The downloaded bundle's SHA-256 ($actual) doesn't match the release's ($expected). Nothing was changed."
    }
    Write-Info "SHA-256 matches the release: $actual"
}

if ($BundleZip) {
    if (-not (Test-Path $BundleZip)) { throw "Bundle not found: $BundleZip" }
    Write-Step "Expanding release bundle"
    Expand-Archive -Path $BundleZip -DestinationPath $staging -Force
    $appSrc   = Get-ChildItem -Path $staging -Recurse -Directory -Filter 'app' | Select-Object -First 1 -ExpandProperty FullName
    $manifest = Get-ChildItem -Path $staging -Recurse -Filter 'migrations-sqlserver.txt' | Select-Object -First 1 -ExpandProperty FullName
    $verFile  = Get-ChildItem -Path $staging -Recurse -Filter 'VERSION.txt' | Select-Object -First 1 -ExpandProperty FullName
    if ($verFile) { $targetVersion = ((Get-Content $verFile | Where-Object { $_ -match 'Version:' }) -replace 'Version:\s*','').Trim() }
    if (-not $appSrc) { throw "The bundle does not contain an 'app' folder: $BundleZip" }

    # WF-70: the upgrade is run by the release's own script, not by this one. -Version runs from the kept copy, which is
    # the previous release's: a fix to the upgrade itself (the warm-up, BUG-260/261) would otherwise reach only the
    # upgrade after the one that ships it. The bundle's script, run on the same zip, finds itself and carries on.
    $bundleScript = Get-ChildItem -Path $staging -Recurse -Filter 'Upgrade-CaseBook.ps1' |
        Where-Object { $_.Directory.Name -eq 'deploy' } | Select-Object -First 1 -ExpandProperty FullName
    if ($bundleScript -and (Get-FileHash $bundleScript).Hash -ne (Get-FileHash $MyInvocation.MyCommand.Path).Hash) {
        $accepted = (Get-Command $bundleScript).Parameters.Keys
        $pass = @{}
        foreach ($k in $PSBoundParameters.Keys) {
            if ($k -notin 'BundleZip', 'Version', 'Repository', 'Proxy' -and $k -in $accepted) { $pass[$k] = $PSBoundParameters[$k] }
        }
        $pass.BundleZip = $BundleZip
        Write-Step "Handing over to the upgrade script in the $(if ($targetVersion) { $targetVersion } else { 'new' }) bundle"
        & $bundleScript @pass
        return
    }
}
elseif ($AppSource) {
    if (-not (Test-Path (Join-Path $AppSource 'IncidentManager.Web.dll'))) {
        throw "-AppSource '$AppSource' does not contain IncidentManager.Web.dll."
    }
    $appSrc = (Resolve-Path $AppSource).Path
}
else {
    Write-Step "Building from source (dotnet publish)"
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw "-Build needs the .NET 10 SDK ('dotnet') on this host." }
    $appSrc = Join-Path $staging 'app'
    & dotnet publish (Join-Path $repoRoot 'src\IncidentManager.Web\IncidentManager.Web.csproj') -c Release -o $appSrc --nologo
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed (exit $LASTEXITCODE)." }
}
# When building/using a raw app folder, derive the migration manifest from the repo (same lineage).
if (-not $manifest) {
    $migDir = Join-Path $repoRoot 'src\IncidentManager.Migrations.SqlServer\Migrations'
    if (Test-Path $migDir) {
        $manifest = Join-Path $staging 'migrations-sqlserver.txt'
        Get-ChildItem $migDir -Filter '*.cs' |
            Where-Object { $_.Name -match '^\d+_' -and $_.Name -notmatch '\.Designer\.cs$' } |
            ForEach-Object { $_.BaseName } | Sort-Object | Set-Content -Path $manifest -Encoding utf8
    }
}
if (-not (Test-Path (Join-Path $appSrc 'IncidentManager.Web.dll'))) { throw "Staged build is missing IncidentManager.Web.dll ($appSrc)." }
# WF-72: an app folder or a build has no VERSION.txt; read the version stamped into the app (a release build's), so the
# site's VERSION.txt (kept across deploys) doesn't go on naming the build this one replaced.
if (-not $targetVersion) {
    $stamped = ([string](Get-Item (Join-Path $appSrc 'IncidentManager.Web.dll')).VersionInfo.ProductVersion) -replace '[+-].*$', ''
    $targetVersion = if ($stamped -match '^\d+\.\d+\.\d+$' -and $stamped -ne '1.0.0') { "v$stamped" } else { 'development build' }
}

# --- 3. Preflight -------------------------------------------------------------
Write-Step "Preflight checks"

# The ASP.NET Core Module, wherever this PowerShell can see it. A 32-bit PowerShell (Windows PowerShell (x86))
# has System32 redirected to SysWOW64 and $env:ProgramFiles pointed at "Program Files (x86)", so check the real
# 64-bit locations (Sysnative, ProgramW6432) and the module's registry key in both views as well.
function Test-AspNetCoreModule {
    foreach ($p in @((Join-Path $env:WINDIR 'System32\inetsrv\aspnetcorev2.dll'),
                     (Join-Path $env:WINDIR 'Sysnative\inetsrv\aspnetcorev2.dll'))) {
        if (Test-Path $p) { return $true }
    }
    foreach ($view in 'Registry64', 'Registry32') {
        try {
            $k = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', $view).OpenSubKey('SOFTWARE\Microsoft\IIS Extensions\IIS AspNetCore Module V2')
            if ($k) { $k.Dispose(); return $true }
        } catch { }
    }
    $pf64 = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
    return (Test-Path (Join-Path $pf64 'IIS\Asp.Net Core Module\V2'))
}

# 3a. ASP.NET Core Module (IIS can't host the app without it -> HTTP 500.19).
if (-not (Test-AspNetCoreModule)) {
    throw "ASP.NET Core Module not installed. Install the .NET 10 Hosting Bundle, run 'iisreset', then retry."
}

# 3b. The ASP.NET Core shared framework the app targets (.NET 10) must be present, or the app
# fails to start with 500.30/500.31. This is the classic trap when the runtime lags the app.
# The 64-bit runtime's folder, even from a 32-bit shell (where $env:ProgramFiles is "Program Files (x86)").
$aspNetRoot = Join-Path $(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }) 'dotnet\shared\Microsoft.AspNetCore.App'
$hasNet10 = (Test-Path $aspNetRoot) -and (Get-ChildItem $aspNetRoot -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '10.*' })
if (-not $hasNet10) {
    throw ("The .NET 10 ASP.NET Core runtime was not found under $aspNetRoot. Install the .NET 10 Hosting " +
           "Bundle (not just the SDK), run 'iisreset', then retry -- otherwise the app fails to start (500.30).")
}
Write-Info "ASP.NET Core Module + .NET 10 runtime present."

# 3c. SQL reachable.
try { [void](Invoke-SqlScalar 'SELECT 1') } catch { throw "Cannot reach the database $DbName on $SqlInstance ($($_.Exception.Message))." }
Write-Info "Database reachable."

# 3d. MIGRATION-COMPATIBILITY -- the check that prevents the "object already exists" startup crash.
# Compare the applied migrations recorded in __EFMigrationsHistory against the release's manifest.
if ($manifest -and (Test-Path $manifest)) {
    $expected = @(Get-Content $manifest | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })
    $historyExists = [int](Invoke-SqlScalar "IF OBJECT_ID('dbo.__EFMigrationsHistory') IS NULL SELECT 0 ELSE SELECT 1")
    $hasAppSchema  = [int](Invoke-SqlScalar "IF OBJECT_ID('dbo.Cases') IS NULL SELECT 0 ELSE SELECT 1")
    $applied = @()
    if ($historyExists -eq 1) { $applied = @(Invoke-SqlColumn "SELECT MigrationId FROM dbo.__EFMigrationsHistory ORDER BY MigrationId") }

    $unknownApplied = @($applied | Where-Object { $expected -notcontains $_ })
    $pending        = @($expected | Where-Object { $applied -notcontains $_ })
    $baseline       = $expected | Select-Object -First 1   # the InitialCreate this release expects

    if ($applied.Count -eq 0 -and $hasAppSchema -eq 1) {
        throw ("MIGRATION MISMATCH: the database has application tables (e.g. Cases) but no migration history " +
               "matching this release. Applying this build would try to recreate existing tables and the app " +
               "would fail to start ('There is already an object named ...'). Resolve before deploying: reconcile " +
               "the migration history, or (if the data is disposable) reset the database. See docs/UPGRADE.md.")
    }
    if ($unknownApplied.Count -gt 0) {
        throw ("MIGRATION MISMATCH: the database records migration(s) this release does not contain " +
               "($([string]::Join(', ', ($unknownApplied | Select-Object -First 5)))). The database is on a " +
               "different or newer lineage than this build -- do NOT deploy it over this database. See docs/UPGRADE.md.")
    }
    if ($hasAppSchema -eq 1 -and $baseline -and ($applied -notcontains $baseline)) {
        throw ("MIGRATION MISMATCH: this release's initial migration ('$baseline') is not in the database's " +
               "history, but application tables exist -- the migration lineage diverged between the deployed " +
               "version and this build. Deploying would crash on startup. See docs/UPGRADE.md.")
    }
    if ($pending.Count -eq 0) { Write-Info "Migrations: database already at this release's schema (no pending migrations)." }
    else { Write-Info ("Migrations: {0} pending will apply on first request -- {1}" -f $pending.Count, [string]::Join(', ', $pending)) }
} else {
    Write-Warn2 "No migration manifest available -- skipping the compatibility preflight (cannot pre-detect a lineage mismatch)."
}

# 3e. DATA-FOLDER SETTINGS -- every store the release keeps under the data root must be configured. A setting
# added in a later release is missing from an older install's appsettings.Production.json, and its store then
# falls back to App_Data under the read-only web root and fails on first use (Access denied).
$template = $null
if ($appSrc) { $template = Get-ChildItem -Path (Split-Path -Parent $appSrc) -Recurse -Filter 'appsettings.Production.template.json' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName }
if (-not $template) { $t2 = Join-Path $deployDir 'appsettings.Production.template.json'; if (Test-Path $t2) { $template = $t2 } }
$missingData = @()
if ($template) {
    # Every string the template sets to "__DATA_ROOT__\..." -> (path in the JSON, suffix under the data root).
    function Get-DataRootSettings($node, [string]$prefix) {
        foreach ($prop in $node.PSObject.Properties) {
            if ($prop.Name -eq '//') { continue }
            $path = if ($prefix) { "${prefix}:$($prop.Name)" } else { $prop.Name }
            if ($prop.Value -is [string] -and $prop.Value -like '__DATA_ROOT__*') {
                [pscustomobject]@{ Path = $path; Suffix = $prop.Value.Substring('__DATA_ROOT__'.Length).TrimStart('\') }
            } elseif ($prop.Value -is [System.Management.Automation.PSCustomObject]) { Get-DataRootSettings $prop.Value $path }
        }
    }
    function Get-JsonValue($node, [string]$path) {
        foreach ($part in $path.Split(':')) { if ($null -eq $node -or -not $node.PSObject.Properties[$part]) { return $null }; $node = $node.$part }
        return $node
    }
    $wanted  = @(Get-DataRootSettings (Get-Content $template -Raw | ConvertFrom-Json) '')
    $liveCfg = Get-Content $prodSettings -Raw | ConvertFrom-Json
    # The data root, from a setting the install already has (value = <data root>\<suffix>), unless given.
    if (-not $DataRoot) {
        foreach ($w in $wanted) {
            $v = Get-JsonValue $liveCfg $w.Path
            if ($v -is [string] -and $v.EndsWith('\' + $w.Suffix, [StringComparison]::OrdinalIgnoreCase)) {
                $DataRoot = $v.Substring(0, $v.Length - $w.Suffix.Length - 1); break
            }
        }
    }
    $missingAll = @($wanted | Where-Object { -not (Get-JsonValue $liveCfg $_.Path) })
    # Only plain storage folders are filled in automatically. The seal signing key is never moved for you: a new
    # location would orphan the existing key, so a missing path stops the upgrade. Anything else (the session key
    # ring, the backup-status file an external job writes) is reported for the admin to set.
    $missingData  = @($missingAll | Where-Object { $_.Path -like '*:RootPath' -or $_.Path -eq 'Integrity:ExportPath' })
    # F-23: a key from the certificate store or CyberArk doesn't use the file path.
    $keySource    = "$(Get-JsonValue $liveCfg 'Integrity:SigningKey:Source')"
    $keyIsFile    = (-not $keySource) -or ($keySource -ieq 'File')
    $missingKey   = @($missingAll | Where-Object { $_.Path -eq 'Integrity:SigningKeyPath' -and $keyIsFile })
    $missingAll   = @($missingAll | Where-Object { $_.Path -ne 'Integrity:SigningKeyPath' -or $keyIsFile })
    $missingOther = @($missingAll | Where-Object { $missingData -notcontains $_ -and $missingKey -notcontains $_ })
    if ($missingKey.Count -gt 0) {
        throw ("appsettings.Production.json has no Integrity:SigningKeyPath. It isn't added automatically because a new " +
               "location would orphan the existing seal signing key. Find where the key lives today, set the path to it " +
               "(see deploy/appsettings.Production.template.json and OPERATIONS.md section 2), then re-run.")
    }
    foreach ($o in $missingOther) {
        Write-Warn2 "Not set: $($o.Path) (the template uses <data root>\$($o.Suffix)). Not changed by the upgrade; set it when convenient."
    }
    if ($missingData.Count -eq 0) { Write-Info "Data-folder settings: all present." }
    elseif (-not $DataRoot) {
        throw ("appsettings.Production.json is missing data-folder setting(s) this release uses (" +
               (($missingData | ForEach-Object { $_.Path }) -join ', ') + ") and the data root can't be worked out " +
               "from the others. Re-run with -DataRoot <your data root, e.g. E:\CaseBookData> so they can be added.")
    } else {
        Write-Warn2 ("Data-folder settings missing -- will be added under $DataRoot after the backup: " +
                     (($missingData | ForEach-Object { "$($_.Path) = $(Join-Path $DataRoot $_.Suffix)" }) -join '; '))
    }
} else {
    Write-Warn2 "No appsettings.Production.template.json found -- skipping the data-folder settings check."
}

# --- 4. Confirm ---------------------------------------------------------------
$currentVerFile = Join-Path $SitePath 'VERSION.txt'
$currentVersion = if (Test-Path $currentVerFile) { ((Get-Content $currentVerFile | Where-Object { $_ -match 'Version:' }) -replace 'Version:\s*','').Trim() } else { '(unknown)' }
Write-Host ""
Write-Host "Ready to upgrade '$SiteName':" -ForegroundColor White
Write-Host "    Current version : $currentVersion"
Write-Host "    Target version  : $(if ($targetVersion) { $targetVersion } else { '(from source/app folder)' })"
Write-Host "    Site path       : $SitePath"
Write-Host "    Database        : $DbName on $SqlInstance"
Write-Host ""
if (-not $Force -and -not $PSCmdlet.ShouldProcess($SiteName, "Upgrade CaseBook")) {
    $ans = Read-Host "Proceed with backup + deploy? (y/N)"
    if ($ans -notmatch '^(y|yes)$') { Write-Warn2 "Aborted by user."; return }
}

# --- 5. Backups (the rollback point today's incident lacked) ------------------
if (-not $BackupRoot) { $BackupRoot = Join-Path (Split-Path -Parent $SitePath) "casebook-upgrade-backups\$stamp" }
New-Item -ItemType Directory -Force -Path $BackupRoot | Out-Null

if (-not $SkipDbBackup) {
    Write-Step "Backing up the database (server-side, default backup directory)"
    $bakName = "$DbName-preupgrade-$stamp.bak"
    # BUG-135: COPY_ONLY, so this extra full backup doesn't become the base of the scheduled differentials (they'd
    # need this file to restore, wherever it ends up).
    try {
        Invoke-SqlNonQuery "BACKUP DATABASE [$DbName] TO DISK = N'$bakName' WITH COPY_ONLY, INIT, COMPRESSION, NAME = N'CaseBook pre-upgrade $stamp';" 600
        $bakDir = [string](Invoke-SqlScalar "SELECT CAST(SERVERPROPERTY('InstanceDefaultBackupPath') AS nvarchar(4000))")
        Write-Info "DB backup: $(if ($bakDir) { Join-Path $bakDir $bakName } else { $bakName })"
    } catch {
        # COMPRESSION isn't supported on every edition -- retry without it before giving up.
        try {
            Invoke-SqlNonQuery "BACKUP DATABASE [$DbName] TO DISK = N'$bakName' WITH COPY_ONLY, INIT, NAME = N'CaseBook pre-upgrade $stamp';" 600
            Write-Info "DB backup written (uncompressed): $bakName"
        } catch { throw "Database backup failed ($($_.Exception.Message)). Fix it, or re-run with -SkipDbBackup if your backup is handled externally." }
    }
} else { Write-Warn2 "Skipping DB backup (-SkipDbBackup)." }

Write-Step "Backing up config + current binaries (rollback point)"
Copy-Item $prodSettings (Join-Path $BackupRoot 'appsettings.Production.json') -Force
$rollbackDir = Join-Path $BackupRoot 'site-rollback'
# Snapshot the live site so a failed upgrade can be reverted. /XD logs keeps the snapshot lean.
& robocopy $SitePath $rollbackDir /E /XD logs /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "Failed to snapshot the current site for rollback (robocopy exit $LASTEXITCODE)." }
Write-Info "Rollback snapshot: $rollbackDir"

# --- 5b. Add any missing data-folder settings (the config is backed up above) ---------
if ($missingData.Count -gt 0) {
    Write-Step "Adding missing data-folder settings to appsettings.Production.json"
    $liveCfg = Get-Content $prodSettings -Raw | ConvertFrom-Json
    # BUG-144: a new store folder gets the app identity's Modify, as the installer grants each store. Copying the data
    # root's ACL isn't enough: after the BUG-134 lockdown the root gives the app only read.
    $pool = Get-Item "IIS:\AppPools\$AppPoolName"
    $appIdentity = if ($pool.processModel.identityType -eq 'SpecificUser' -and $pool.processModel.userName) {
        $pool.processModel.userName } else { "IIS APPPOOL\$AppPoolName" }
    foreach ($m in $missingData) {
        $value = Join-Path $DataRoot $m.Suffix
        $node = $liveCfg; $parts = $m.Path.Split(':')
        for ($i = 0; $i -lt $parts.Length - 1; $i++) {
            if (-not $node.PSObject.Properties[$parts[$i]]) { $node | Add-Member -NotePropertyName $parts[$i] -NotePropertyValue ([pscustomobject]@{}) }
            $node = $node.($parts[$i])
        }
        if ($node.PSObject.Properties[$parts[-1]]) { $node.($parts[-1]) = $value } else { $node | Add-Member -NotePropertyName $parts[-1] -NotePropertyValue $value }
        # A folder setting gets its folder; a file setting (e.g. a key path) gets its parent folder. New folders inherit
        # the data root's ACL (SYSTEM, Administrators, the app's read) and add the app's Modify.
        $dir = if ([IO.Path]::GetExtension($value)) { Split-Path -Parent $value } else { $value }
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            $acl = Get-Acl $dir
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $appIdentity, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            Set-Acl -Path $dir -AclObject $acl
        }
        Write-Info "$($m.Path) = $value"
    }
    $liveCfg | ConvertTo-Json -Depth 32 | Set-Content -Path $prodSettings -Encoding UTF8
}

# --- 6. Deploy ---------------------------------------------------------------
Write-Step "Stopping app pool '$AppPoolName'"
# REV-72: until the worker has exited and let go of the DLLs, not a fixed few seconds: a busy server's worker can take
# far longer (open circuits, background jobs), and the copy then failed part way and went into rollback.
Stop-CaseBookAppPool -Name $AppPoolName

# BUG-183: what the database has applied before the new build runs, so a rollback can tell whether it migrated.
$appliedBeforeDeploy = @()
try { $appliedBeforeDeploy = @(Invoke-SqlColumn "IF OBJECT_ID('dbo.__EFMigrationsHistory') IS NOT NULL SELECT MigrationId FROM dbo.__EFMigrationsHistory") }
catch { Write-Warn2 "Couldn't read the migration history before deploying: $($_.Exception.Message)" }

# BUG-250: a rollback copy that fails (often the same locked DLL that failed the deploy) leaves a mix of old and new
# files. Say so and leave the pool stopped, rather than start it and report the previous build restored.
function Restore-PreviousBuild([string] $why) {
    & robocopy $rollbackDir $SitePath /MIR /XF appsettings.Production.json /XD logs /R:5 /W:3 /NFL /NDL /NJH /NJS /NP | Out-Null
    $restoreRc = $LASTEXITCODE
    if ($restoreRc -ge 8) {
        Stop-WebAppPool -Name $AppPoolName -ErrorAction SilentlyContinue
        throw ("Upgrade failed ($why), and restoring the previous build's files failed too (robocopy exit $restoreRc), so " +
               "the site folder holds a mix of old and new files. The app pool is left STOPPED. Copy the snapshot " +
               "$rollbackDir over $SitePath (keep appsettings.Production.json and logs), then start the app pool. " +
               "If the new build applied migrations, restore the pre-upgrade DB backup first (docs/UPGRADE.md).")
    }
}

Write-Step "Deploying new binaries (preserving appsettings.Production.json + logs)"
# /MIR removes stale files from the prior version; /XF + /XD keep the production config, the version record and logs.
& robocopy $appSrc $SitePath /MIR /XF appsettings.Production.json VERSION.txt /XD logs /R:2 /W:2 /NFL /NDL /NJH /NJS /NP | Out-Null
$rc = $LASTEXITCODE
if ($rc -ge 8) {
    Write-Warn2 "Deploy copy failed (robocopy exit $rc) -- rolling back binaries."
    Restore-PreviousBuild "the deploy copy failed (robocopy exit $rc)"
    Start-WebAppPool -Name $AppPoolName -ErrorAction SilentlyContinue
    throw "Upgrade aborted during file copy; the previous build was restored."
}

# BUG-95/137: as the installer now sets them, for pools installed before it did: no scheduled recycle, no overlap.
Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name recycling.periodicRestart.time -Value '00:00:00'
Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name recycling.disallowOverlappingRotation -Value $true

Write-Step "Starting app pool"
Start-WebAppPool -Name $AppPoolName

# --- 7. Warm up (applies pending migrations) + verify ------------------------
Write-Step "Warming up (the first request applies pending migrations)"
# BUG-249: only the app's own answer proves it started; a 5xx or a connection failure means it didn't. Tolerate a
# self-signed cert during this local probe.
# BUG-260: the probe goes straight to the site, never through the administrator's proxy, and doesn't follow redirects;
# each attempt says what it got.
# BUG-261: and only CaseBook's own answer counts: the import schema itself. IIS can answer /api with its own 404 (the
# StaticFile handler, when /api doesn't reach the app), which v1.6.1 wrongly took for the app.
function Invoke-SiteProbe([string] $Url, [switch] $WithCredentials) {
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.Proxy = $null
    $req.AllowAutoRedirect = $false
    $req.Timeout = 30000
    $req.ReadWriteTimeout = 30000
    $req.UserAgent = 'CaseBook-Upgrade'
    if ($WithCredentials) { $req.UseDefaultCredentials = $true }
    $resp = $null
    try { $resp = $req.GetResponse() }
    catch {
        $ex = $_.Exception
        while ($ex -and $ex -isnot [System.Net.WebException]) { $ex = $ex.InnerException }
        if ($ex -and $ex.Response) { $resp = $ex.Response }
        else {
            $msg = if ($ex) { "$($ex.Status): $($ex.Message)" } else { $_.Exception.Message }
            return @{ Status = $null; Detail = $msg; Location = $null; Body = '' }
        }
    }
    try {
        $body = ''
        try {
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $buf = New-Object char[] 4096
            $n = $reader.Read($buf, 0, $buf.Length)
            if ($n -gt 0) { $body = New-Object string($buf, 0, $n) }
        } catch { }
        $detail = "$([int]$resp.StatusCode) $($resp.StatusDescription)"
        if ($body -match '<title>([^<]+)</title>') { $detail += " ($($Matches[1].Trim()))" }
        return @{ Status = [int]$resp.StatusCode; Detail = $detail; Location = $resp.Headers['Location']; Body = $body }
    } finally { $resp.Close() }
}
# What an answer means: CaseBook started ('started'), Windows authentication answered instead of the app ('auth'),
# something other than CaseBook answered ('other', e.g. IIS's own 404), it crashed ('crashed'), or nothing yet ('none').
# The schema probe needs the schema itself; the signed-in probe of the site root takes any page or redirect.
function Get-ProbeVerdict($probe, [switch] $Schema) {
    $c = $probe.Status
    if ($null -eq $c -or $c -eq 407) { return 'none' }
    # WF-73: 500.37 is IIS saying the app hasn't finished starting within its startupTimeLimit (a long migration); the
    # next request starts it again where the migrations left off, so it's still starting, not a crash.
    if ($c -eq 500 -and $probe.Body -match '500\.37') { return 'none' }
    if ($c -ge 500) { return 'crashed' }
    if ($c -in 401,403) { return 'auth' }
    if ($Schema) { if ($c -eq 200 -and $probe.Body -match '"\$schema"') { return 'started' } else { return 'other' } }
    if ($c -ge 200 -and $c -lt 400) { return 'started' }
    return 'other'
}

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
$deadline = (Get-Date).AddSeconds($WarmupTimeoutSec)
$started = $false; $lastStatus = $null; $verdict = 'none'; $lastDetail = $null
while ((Get-Date) -lt $deadline) {
    $probe = Invoke-SiteProbe $ProbeUrl
    if ($probe.Detail -ne $lastDetail) { Write-Info "Probe: $($probe.Detail)"; $lastDetail = $probe.Detail }
    $lastStatus = $probe.Status
    $verdict = Get-ProbeVerdict $probe -Schema
    if ($verdict -eq 'started') { $started = $true; break }
    if ($verdict -in 'crashed','auth','other') { break }
    Start-Sleep -Seconds 3                                                              # still starting / not yet listening
}
if ($verdict -in 'auth','other') {
    if ($verdict -eq 'auth') {
        # /api isn't anonymous on this site (installed before the API carve-out, or changed since), so IIS answered.
        Write-Warn2 "$ProbeUrl answered $lastStatus (Windows authentication, not the app)."
    } else {
        Write-Warn2 ("$ProbeUrl answered '$lastDetail', which isn't CaseBook: IIS isn't passing /api to the app, so API " +
                     "imports can't reach it either. See docs/UPGRADE.md (v1.6.2).")
    }
    # Ask the site root as a signed-in user instead: a page there is the app's own answer.
    Write-Warn2 "Probing $HealthUrl as the signed-in user instead."
    $probe = Invoke-SiteProbe $HealthUrl -WithCredentials
    Write-Info "Probe: $($probe.Detail)"
    $lastStatus = $probe.Status
    switch (Get-ProbeVerdict $probe) {
        'started' { $started = $true }
        'auth' {
            Write-Warn2 ("Couldn't prove the new build started: the site root was answered by Windows authentication too. " +
                         "Open $HealthUrl in a browser now; if it fails, run this script's rollback steps by hand " +
                         "(docs/UPGRADE.md).")
            $started = $true
        }
        'other' { Write-Warn2 "$HealthUrl answered '$($probe.Detail)', which isn't a CaseBook page." }
    }
}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
if (-not $started -and $null -eq $lastStatus) {
    Write-Warn2 ("No answer from $ProbeUrl within $WarmupTimeoutSec seconds (last: $lastDetail). If the site works in a " +
                 "browser, this host can't reach it by that name: pass -HealthUrl with an address it can reach.")
}

if (-not $started -or ($lastStatus -ge 500)) {
    Write-Warn2 "App did not come up (last status: $(if($lastStatus){$lastStatus}else{'no response'})). Checking the event log..."
    try {
        Get-WinEvent -FilterHashtable @{ LogName='Application'; Level=2; StartTime=(Get-Date).AddMinutes(-10) } -MaxEvents 5 -ErrorAction SilentlyContinue |
            Where-Object { $_.ProviderName -match 'AspNetCore|\.NET Runtime' } |
            ForEach-Object { Write-Host "    [$($_.TimeCreated)] $($_.Message.Split([Environment]::NewLine)[0])" -ForegroundColor Red }
    } catch {}
    Write-Warn2 "Rolling back to the previous build."
    try { Stop-CaseBookAppPool -Name $AppPoolName }   # REV-72
    catch { Write-Warn2 $_.Exception.Message }
    Restore-PreviousBuild "the new build didn't start"
    # BUG-183: if the new build recorded migrations, the previous build would run against a schema (and records) it
    # doesn't know: from v1.5.2 on, row hashes and seals are in formats older builds read as tampered. Leave the pool
    # stopped until the database backup is restored.
    $migrated = @()
    try {
        $now = @(Invoke-SqlColumn "IF OBJECT_ID('dbo.__EFMigrationsHistory') IS NOT NULL SELECT MigrationId FROM dbo.__EFMigrationsHistory")
        $migrated = @($now | Where-Object { $appliedBeforeDeploy -notcontains $_ })
    } catch { Write-Warn2 "Couldn't read the migration history to check what the new build applied: $($_.Exception.Message)" }
    if ($migrated.Count -gt 0) {
        throw ("Upgrade failed -- the previous build's files are back, but the new build had already applied " +
               "$($migrated.Count) migration(s) ($([string]::Join(', ', ($migrated | Select-Object -First 3)))), so the app pool " +
               "is left STOPPED. Restore the pre-upgrade DB backup (in the SQL default backup directory), then start the " +
               "app pool. Running the previous build on the upgraded database would raise false tamper alarms. " +
               "Review the event-log error above and docs/UPGRADE.md.")
    }
    Start-WebAppPool -Name $AppPoolName -ErrorAction SilentlyContinue
    throw ("Upgrade failed -- the previous build has been restored and the app pool restarted. " +
           "If the new build had begun applying migrations, restore the DB backup in the SQL default backup " +
           "directory before retrying. Review the event-log error above and docs/UPGRADE.md.")
}

# Record the deployed version so the next upgrade can show current -> target, and (PROD-50) what it was upgraded from,
# when and by whom, which Administration > Updates shows.
if ($targetVersion) {
    $verLines = @("Version: $targetVersion")
    if ($currentVersion -and $currentVersion -ne '(unknown)' -and $currentVersion -ne $targetVersion) { $verLines += "Previous: $currentVersion" }
    $verLines += "Upgraded: $(Get-Date -Format 'yyyy-MM-dd HH:mm zzz')"
    $verLines += "By: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Set-Content -Path (Join-Path $SitePath 'VERSION.txt') -Value $verLines -Encoding utf8
}

# PROD-50: keep this release's deploy scripts beside the site (admin-only), so the next upgrade is -Version vX.Y.Z.
try {
    $newDeploy = if ($BundleZip) { Get-ChildItem -Path $staging -Recurse -Directory -Filter 'deploy' | Select-Object -First 1 -ExpandProperty FullName } else { $deployDir }
    if (-not $newDeploy) { $newDeploy = $deployDir }
    $kept = Publish-CaseBookDeployScripts -SourceDeployDir $newDeploy -SitePath $SitePath -SiteName $SiteName
    if ($kept) { Write-Info "Deploy scripts kept in $kept (next time: & '$kept\Upgrade-CaseBook.ps1' -Version <vX.Y.Z>)" }
} catch { Write-Warn2 "Couldn't keep a copy of the deploy scripts beside the site: $($_.Exception.Message)" }

Write-Step "Upgrade complete."
Write-Host @"

The app responded ($lastStatus) -- it started and applied any pending migrations.

Verify:
  1. Sign in and open Administration (as an App Admin).
  2. Integrity -> "Verify now" should report the chain VALID.
  3. Open a case and generate a report to confirm the stores.

Backups for rollback are under:
  $BackupRoot
  (config + site-rollback\; the DB backup is in the SQL instance's default backup directory)
"@ -ForegroundColor Green
