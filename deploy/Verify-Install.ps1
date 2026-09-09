#Requires -Version 5.1
<#
.SYNOPSIS
    Readiness + smoke test for a CaseBook deployment.

.DESCRIPTION
    Two checks in one script:

      * PRE-INSTALL readiness (-ConfigFile) - reads the answers file and confirms every
        value RESOLVES in this environment BEFORE you run the heavy install steps: the
        service account and the five AD role groups resolve to real SIDs, the TLS cert is
        present/valid, the site and data paths are sane, SQL is reachable over Windows auth
        (and whether the database exists yet), and the ASP.NET Core Module is installed.
        Catches the common misconfigurations up front instead of mid-publish or mid-DDL.

      * POST-INSTALL smoke test (-Url) - confirms the app pool is running and the site
        answers 200 over Windows integrated auth (the original behaviour).

    Pass -ConfigFile, -Url, or both. Host-specific items that can't be checked from where
    you're running (e.g. the web-host cert on the SQL box) are reported as WARN, not FAIL,
    so it's safe to run on either host - run it on each host before that host's step.

    Read-only: it changes nothing. Verify the tamper-evident chain itself in-app afterwards
    (Integrity -> "Verify now").

.PARAMETER ConfigFile
    Path to the casebook.config.psd1 answers file to validate (pre-install readiness).

.PARAMETER Url
    Base URL for the post-install smoke test, e.g. https://casebook.contoso.com/

.PARAMETER AppPoolName
    IIS application-pool name for the smoke test. Defaults to the answers file's AppPoolName
    (when -ConfigFile is given), else 'CaseBook'.

.EXAMPLE
    # Before installing, on each host:
    .\Verify-Install.ps1 -ConfigFile .\casebook.config.psd1

.EXAMPLE
    # After installing, on the web host:
    .\Verify-Install.ps1 -Url https://casebook.contoso.com/

.EXAMPLE
    # Both at once:
    .\Verify-Install.ps1 -ConfigFile .\casebook.config.psd1 -Url https://casebook.contoso.com/
#>
[CmdletBinding()]
param(
    [string] $ConfigFile,
    [string] $Url,
    [string] $AppPoolName
)

$ErrorActionPreference = 'Stop'
$script:fail = 0
$script:warn = 0
$cfg = $null
function Ok($m)   { Write-Host "  [ OK ] $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "  [FAIL] $m" -ForegroundColor Red;    $script:fail++ }
function Warn($m) { Write-Host "  [WARN] $m" -ForegroundColor Yellow; $script:warn++ }
function Info($m) { Write-Host "  [ .. ] $m" -ForegroundColor Gray }

function Resolve-Account([string] $name) {
    try { [void] ([System.Security.Principal.NTAccount]::new($name)).Translate([System.Security.Principal.SecurityIdentifier]); return $true }
    catch { return $false }
}

if (-not $ConfigFile -and -not $Url) {
    throw "Nothing to check. Pass -ConfigFile <answers.psd1> for a pre-install readiness check, -Url <site> for a post-install smoke test, or both."
}

Write-Host "CaseBook install verification" -ForegroundColor Cyan

# ============================= PRE-INSTALL READINESS ==========================
if ($ConfigFile) {
    Write-Host "`nPre-install readiness (from $ConfigFile)" -ForegroundColor Cyan
    if (-not (Test-Path $ConfigFile)) {
        Bad "Config file not found: $ConfigFile"
    } else {
        try { $cfg = Import-PowerShellDataFile -Path $ConfigFile; Ok "Answers file parses" }
        catch { Bad "Answers file did not parse: $($_.Exception.Message)" }
    }

    if ($cfg) {
        # --- required values present ---
        $req = 'SqlInstance','AppAccount','SitePath','DataRoot','Hostname',
               'AdGroupAnalysts','AdGroupCommanders','AdGroupLeadership','AdGroupLegal','AdGroupAppAdmins'
        $missing = @($req | Where-Object { -not $cfg.ContainsKey($_) -or [string]::IsNullOrWhiteSpace([string]$cfg[$_]) })
        if ($missing.Count) { Bad "Missing required value(s): $($missing -join ', ')" } else { Ok "All required values present" }

        # --- service account ---
        if ([string]$cfg.AppAccount) {
            if (Resolve-Account ([string]$cfg.AppAccount)) { Ok "Service account '$($cfg.AppAccount)' resolves to a SID" }
            else { Bad "Service account '$($cfg.AppAccount)' does not resolve here (must exist in AD; this host must reach a DC)" }
            if (([string]$cfg.AppAccount).EndsWith('$')) { Info "gMSA (passwordless) - ensure it is installed on the web host (Install-ADServiceAccount)" }
            else { Info "Normal service account - Install-CaseBook.ps1 will prompt for its password securely" }
        }

        # --- AD role groups ---
        foreach ($g in 'AdGroupAnalysts','AdGroupCommanders','AdGroupLeadership','AdGroupLegal','AdGroupAppAdmins') {
            $val = [string]$cfg[$g]
            if ([string]::IsNullOrWhiteSpace($val)) { continue }
            if ((Resolve-Account $val) -or (Resolve-Account "$env:USERDOMAIN\$val")) { Ok "AD group '$val' resolves" }
            else { Bad "AD group '$val' ($g) does not resolve - confirm the group name exists in AD" }
        }

        # --- site vs data paths ---
        $sp = ([string]$cfg.SitePath).TrimEnd('\')
        $dr = ([string]$cfg.DataRoot).TrimEnd('\')
        if ($sp -and $dr) {
            if ($dr.ToLower().StartsWith($sp.ToLower())) { Bad "DataRoot '$dr' is inside SitePath '$sp' - keep case evidence OFF the web root" }
            else { Ok "SitePath and DataRoot are separate" }
        }
        foreach ($p in @($cfg.SitePath, $cfg.DataRoot)) {
            if ([string]::IsNullOrWhiteSpace([string]$p)) { continue }
            $root = [System.IO.Path]::GetPathRoot([string]$p)
            if ($root -and (Test-Path $root)) { Ok "Drive $root present (for $p)" }
            else { Warn "Drive $root for '$p' not found here (fine if you're not on the web host; the installer creates the folders, not the volume)" }
        }

        # --- TLS certificate ---
        if ($cfg.ContainsKey('CertificateThumbprint') -and -not [string]::IsNullOrWhiteSpace([string]$cfg.CertificateThumbprint)) {
            $tp = (([string]$cfg.CertificateThumbprint) -replace '\s','').ToUpper()
            $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $tp }
            if (-not $cert) {
                Warn "Cert $tp not found in LocalMachine\My here (must be present on the web host for the 443 binding)"
            } elseif (-not $cert.HasPrivateKey) {
                Bad "Cert $tp has no private key - IIS can't bind TLS with it"
            } elseif ($cert.NotAfter -lt (Get-Date)) {
                Bad "Cert $tp EXPIRED $($cert.NotAfter.ToString('yyyy-MM-dd'))"
            } elseif ($cert.NotAfter -lt (Get-Date).AddDays(30)) {
                Warn "Cert $tp valid but expires soon ($($cert.NotAfter.ToString('yyyy-MM-dd')))"
            } else {
                Ok "Cert $tp present, has private key, valid to $($cert.NotAfter.ToString('yyyy-MM-dd'))"
            }
        } else {
            Warn "No CertificateThumbprint - Install-CaseBook will create an HTTP binding; add TLS before real case data"
        }

        # --- SQL reachability over Windows auth (same path the app uses) ---
        if ([string]$cfg.SqlInstance) {
            $dbName = if (-not [string]::IsNullOrWhiteSpace([string]$cfg.DbName)) { [string]$cfg.DbName } else { 'CaseBook' }
            $cs = "Server=$($cfg.SqlInstance);Database=master;Integrated Security=SSPI;Encrypt=True;" +
                  "TrustServerCertificate=True;Connect Timeout=5;Application Name=CaseBook-Verify"
            try {
                $conn = New-Object System.Data.SqlClient.SqlConnection $cs
                $conn.Open()
                Ok "SQL '$($cfg.SqlInstance)' reachable over Windows auth"
                $dbEsc = $dbName -replace "'", "''"
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = "SELECT DB_ID(N'$dbEsc')"
                $dbId = $cmd.ExecuteScalar()
                if ($dbId -and $dbId -ne [DBNull]::Value) { Info "Database '$dbName' already exists on the instance" }
                else { Info "Database '$dbName' not yet created - Install-Database.ps1 will create it" }
            } catch {
                $first = ($_.Exception.Message -split "`r?`n")[0]
                Warn "Could not connect to SQL '$($cfg.SqlInstance)' from here: $first"
            } finally {
                if ($conn) { $conn.Dispose() }
            }
        }

        # --- web-host capability (only meaningful on the web host) ---
        $ancm = Join-Path $env:WINDIR 'System32\inetsrv\aspnetcorev2.dll'
        if (Test-Path $ancm) { Ok "ASP.NET Core Module present (this host can host the app)" }
        else { Warn ".NET 8 Hosting Bundle / ASP.NET Core Module not found (install it on the WEB host before Install-CaseBook)" }
    }
}

# ============================= POST-INSTALL SMOKE TEST ========================
if ($Url) {
    Write-Host "`nPost-install smoke test ($Url)" -ForegroundColor Cyan
    $pool = if ($AppPoolName) { $AppPoolName }
            elseif ($cfg -and -not [string]::IsNullOrWhiteSpace([string]$cfg.AppPoolName)) { [string]$cfg.AppPoolName }
            else { 'CaseBook' }

    # 1. App pool state
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $state = (Get-WebAppPoolState -Name $pool).Value
        if ($state -eq 'Started') { Ok "App pool '$pool' is Started" }
        else { Bad "App pool '$pool' state is '$state' (expected Started)" }
    } catch { Bad "Could not read app pool '$pool': $($_.Exception.Message)" }

    # 2. HTTP reachability over Windows auth
    try {
        Info "GET $Url (Windows integrated auth)"
        $resp = Invoke-WebRequest -Uri $Url -UseDefaultCredentials -UseBasicParsing -TimeoutSec 30
        if ($resp.StatusCode -eq 200) { Ok "Site responded 200 OK" }
        else { Bad "Unexpected status $($resp.StatusCode)" }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__ 2>$null
        if ($code -eq 401) { Bad "401 Unauthorized - Windows auth not negotiating (check SPNs / that you're a mapped role member)" }
        else { Bad "Request failed: $($_.Exception.Message)" }
    }
}

# ================================== SUMMARY ===================================
Write-Host ""
if ($script:fail -eq 0) {
    $tail = if ($script:warn -gt 0) { " ($($script:warn) warning(s) - review above)" } else { "" }
    if ($ConfigFile -and -not $Url) { Write-Host "Readiness checks passed$tail. Proceed with Install-Database.ps1 / Install-CaseBook.ps1." -ForegroundColor Green }
    elseif ($Url) { Write-Host "All checks passed$tail. Now confirm the chain in-app: Integrity -> 'Verify now' = VALID." -ForegroundColor Green }
    else { Write-Host "All checks passed$tail." -ForegroundColor Green }
    exit 0
} else {
    Write-Host "$($script:fail) check(s) FAILED, $($script:warn) warning(s) - fix the failures above." -ForegroundColor Red
    exit 1
}
