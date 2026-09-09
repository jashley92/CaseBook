#Requires -Version 5.1
<#
.SYNOPSIS
    Interactive generator for the CaseBook install answers file (casebook.config.psd1).

.DESCRIPTION
    Prompts for every value the two installers need - SQL instance, service account,
    IIS site/data paths, hostname, TLS cert, and the five AD role groups - with sensible
    defaults and light validation, then writes a ready-to-use *.psd1 you pass to both
    installers with -ConfigFile. Run it anywhere (a workstation is fine); AD and cert
    checks are best-effort and only warn.

    No password is ever collected or written: a gMSA is passwordless, and a normal service
    account's password is prompted for securely at install time by Install-CaseBook.ps1.

.PARAMETER OutFile
    Where to write the answers file. Default: .\casebook.config.psd1

.EXAMPLE
    .\New-CaseBookConfig.ps1
    .\New-CaseBookConfig.ps1 -OutFile C:\deploy\casebook.config.psd1
#>
[CmdletBinding()]
param(
    [string] $OutFile = (Join-Path (Get-Location) 'casebook.config.psd1')
)

$ErrorActionPreference = 'Stop'

function Ask {
    param(
        [string] $Prompt,
        [string] $Default = '',
        [switch] $Required,
        [string] $Pattern,          # optional regex the answer must match
        [string] $PatternHint
    )
    while ($true) {
        $suffix = if ($Default -ne '') { " [$Default]" } elseif ($Required) { ' (required)' } else { ' (optional, blank to skip)' }
        $raw = Read-Host ("  " + $Prompt + $suffix)
        $val = if ([string]::IsNullOrWhiteSpace($raw)) { $Default } else { $raw.Trim() }
        if ($Required -and [string]::IsNullOrWhiteSpace($val)) { Write-Host "    A value is required." -ForegroundColor Yellow; continue }
        if ($val -ne '' -and $Pattern -and ($val -notmatch $Pattern)) {
            Write-Host "    $PatternHint" -ForegroundColor Yellow; continue
        }
        return $val
    }
}

function Ask-Choice {
    param([string] $Prompt, [string[]] $Options, [string] $Default)
    while ($true) {
        $val = Read-Host ("  " + $Prompt + " (" + ($Options -join '/') + ") [$Default]")
        if ([string]::IsNullOrWhiteSpace($val)) { return $Default }
        $match = $Options | Where-Object { $_ -ieq $val.Trim() }
        if ($match) { return $match }
        Write-Host "    Choose one of: $($Options -join ', ')" -ForegroundColor Yellow
    }
}

function Test-AccountResolves([string] $account) {
    try { [void] ([System.Security.Principal.NTAccount]::new($account)).Translate([System.Security.Principal.SecurityIdentifier]); return $true }
    catch { return $false }
}

Write-Host ""
Write-Host "CaseBook - install answers generator" -ForegroundColor Cyan
Write-Host "Answer the prompts; blank accepts the [default]. Nothing is applied - this only writes $OutFile." -ForegroundColor Gray
Write-Host ""

# --- SQL Server ---------------------------------------------------------------
Write-Host "SQL Server" -ForegroundColor Cyan
$SqlInstance = Ask -Prompt 'SQL instance (HOST or HOST\INSTANCE)' -Default 'SQLHOST\PROD' -Required
$DbName      = Ask -Prompt 'Database name' -Default 'CaseBook' -Required

# --- Service account ----------------------------------------------------------
Write-Host ""
Write-Host "Service account (the IIS app-pool identity AND its SQL login)" -ForegroundColor Cyan
$AppAccount = Ask -Prompt 'Service account (DOMAIN\name; gMSA ends with $)' -Required `
    -Pattern '^[^\\]+\\[^\\]+$' -PatternHint 'Use DOMAIN\name form, e.g. CONTOSO\svc-casebook$ (gMSA) or CONTOSO\svc-casebook.'
if ($AppAccount.EndsWith('$')) {
    Write-Host "    Detected a gMSA (trailing '$') - passwordless. Ensure it is installed on the web host (Install-ADServiceAccount)." -ForegroundColor Gray
} else {
    Write-Host "    Normal service account - Install-CaseBook.ps1 will prompt for its password securely (not stored here)." -ForegroundColor Gray
}
if (-not (Test-AccountResolves $AppAccount)) {
    Write-Host "    NOTE: could not resolve '$AppAccount' from this machine (fine if you're off-domain). It MUST resolve on the target hosts." -ForegroundColor Yellow
}

$SchemaMode = Ask-Choice -Prompt 'Schema mode' -Options @('AppMigrates','DbaApplies') -Default 'AppMigrates'
$DataPath = Ask -Prompt 'SQL data-file folder (.mdf)' -Default ''
$LogPath  = Ask -Prompt 'SQL log-file folder (.ldf)'  -Default ''

# --- Web host / IIS -----------------------------------------------------------
Write-Host ""
Write-Host "Web host / IIS" -ForegroundColor Cyan
$SitePath = Ask -Prompt 'Web root (site path)' -Default 'D:\inetpub\casebook' -Required
$DataRoot = Ask -Prompt 'Data root (evidence/keys/reports - OUTSIDE the web root)' -Default 'E:\CaseBookData' -Required
if ($DataRoot.TrimEnd('\').ToLower().StartsWith($SitePath.TrimEnd('\').ToLower())) {
    Write-Host "    WARNING: the data root is inside the web root. Keep case evidence OFF the web root." -ForegroundColor Yellow
}
$Hostname = Ask -Prompt 'Public hostname (host header)' -Default 'casebook.contoso.com' -Required `
    -Pattern '^[A-Za-z0-9.-]+$' -PatternHint 'Enter a DNS name, e.g. casebook.contoso.com.'
$SiteName    = Ask -Prompt 'IIS site name' -Default 'CaseBook' -Required
$AppPoolName = Ask -Prompt 'IIS app-pool name' -Default 'CaseBook' -Required

# TLS cert: offer to pick from LocalMachine\My, else accept a thumbprint, else none.
$CertificateThumbprint = ''
Write-Host ""
Write-Host "TLS certificate (for the HTTPS binding)" -ForegroundColor Cyan
$certs = @()
try { $certs = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop | Where-Object { $_.HasPrivateKey }) } catch { }
if ($certs.Count -gt 0) {
    Write-Host "  Installed certificates in LocalMachine\My:" -ForegroundColor Gray
    for ($i = 0; $i -lt $certs.Count; $i++) {
        Write-Host ("    [{0}] {1}  (exp {2})  {3}" -f $i, $certs[$i].Subject, $certs[$i].NotAfter.ToString('yyyy-MM-dd'), $certs[$i].Thumbprint)
    }
    $pick = Ask -Prompt 'Cert number to bind, a full thumbprint, or blank for HTTP-only' -Default ''
    if ($pick -match '^\d+$' -and [int]$pick -lt $certs.Count) {
        $CertificateThumbprint = $certs[[int]$pick].Thumbprint
    } elseif ($pick -ne '') {
        $CertificateThumbprint = ($pick -replace '\s','').ToUpper()
    }
} else {
    Write-Host "  (No private-key certs found here - that's fine if you're not on the web host.)" -ForegroundColor Gray
    $CertificateThumbprint = Ask -Prompt 'TLS cert thumbprint, or blank for HTTP-only' -Default '' `
        -Pattern '^[0-9A-Fa-f]{40}$' -PatternHint 'A thumbprint is 40 hex characters (or leave blank).'
}
if ($CertificateThumbprint -eq '') {
    Write-Host "    No cert chosen - an HTTP binding will be created for a first smoke test. Add TLS before real data." -ForegroundColor Yellow
}

# --- AD role groups -----------------------------------------------------------
Write-Host ""
Write-Host "AD security groups mapped to the five roles (your real group names)" -ForegroundColor Cyan
function Ask-Group([string] $role, [string] $default) {
    $g = Ask -Prompt "$role group" -Default $default -Required
    if (-not (Test-AccountResolves "$env:USERDOMAIN\$g") -and -not (Test-AccountResolves $g)) {
        Write-Host "    NOTE: couldn't resolve group '$g' from here - confirm the name exists in AD." -ForegroundColor Yellow
    }
    return $g
}
$AdGroupAnalysts   = Ask-Group 'Analysts'            'SOC-Analysts'
$AdGroupCommanders = Ask-Group 'Incident Commanders' 'SOC-IncidentCommanders'
$AdGroupLeadership = Ask-Group 'Leadership/Managers'  'SOC-Leadership'
$AdGroupLegal      = Ask-Group 'Legal/Privacy'        'Legal-Privacy'
$AdGroupAppAdmins  = Ask-Group 'App Admins'           'SOC-AppAdmins'

# --- Optional email -----------------------------------------------------------
Write-Host ""
Write-Host "Email (optional - stays disabled until enabled in-app)" -ForegroundColor Cyan
$SmtpHost   = Ask -Prompt 'SMTP host' -Default ''
$MailDomain = Ask -Prompt 'Mail domain (From = casebook@<domain>)' -Default ''

# --- Write the answers file ---------------------------------------------------
function Q([string] $v) { "'" + ($v -replace "'", "''") + "'" }

$body = @"
# CaseBook install answers - generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') by New-CaseBookConfig.ps1.
# Pass to the installers with -ConfigFile. Sensitive (names AD groups/hosts/account); do NOT commit.
# Holds NO passwords - gMSA is passwordless; a normal account's password is prompted at install time.
@{
    SqlInstance = $(Q $SqlInstance)
    DbName      = $(Q $DbName)
    AppAccount  = $(Q $AppAccount)
    SchemaMode  = $(Q $SchemaMode)
    DataPath    = $(Q $DataPath)
    LogPath     = $(Q $LogPath)

    SitePath    = $(Q $SitePath)
    DataRoot    = $(Q $DataRoot)
    Hostname    = $(Q $Hostname)
    CertificateThumbprint = $(Q $CertificateThumbprint)
    SiteName    = $(Q $SiteName)
    AppPoolName = $(Q $AppPoolName)

    AdGroupAnalysts   = $(Q $AdGroupAnalysts)
    AdGroupCommanders = $(Q $AdGroupCommanders)
    AdGroupLeadership = $(Q $AdGroupLeadership)
    AdGroupLegal      = $(Q $AdGroupLegal)
    AdGroupAppAdmins  = $(Q $AdGroupAppAdmins)

    SmtpHost    = $(Q $SmtpHost)
    MailDomain  = $(Q $MailDomain)
}
"@

if (Test-Path $OutFile) {
    $ow = Ask-Choice -Prompt "`n$OutFile exists. Overwrite?" -Options @('y','n') -Default 'n'
    if ($ow -eq 'n') { Write-Host "Aborted - existing file left untouched." -ForegroundColor Yellow; exit 1 }
}
$body | Set-Content -Path $OutFile -Encoding utf8

# Validate it loads and round-trips.
$check = Import-PowerShellDataFile -Path $OutFile

Write-Host ""
Write-Host "Wrote $OutFile" -ForegroundColor Green
Write-Host "Next:" -ForegroundColor Green
Write-Host "  1. Copy it to the SQL host and run:   .\Install-Database.ps1 -ConfigFile .\casebook.config.psd1" -ForegroundColor Green
Write-Host "  2. Copy it to the web host and run:    .\Install-CaseBook.ps1 -ConfigFile .\casebook.config.psd1" -ForegroundColor Green
if (-not $AppAccount.EndsWith('$')) {
    Write-Host "     (You'll be prompted for $AppAccount's password during step 2.)" -ForegroundColor Green
}
