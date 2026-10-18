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
        answers 200 over Windows integrated auth (the original behaviour), and that /api,
        /health, /branding/logo and /agenda/feed.ics reach the app without a sign-in.

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
# REV-73: Windows PowerShell 5.1 offers only SSL3/TLS 1.0 by default unless the host sets SchUseStrongCrypto, and a host
# with those turned off then refuses every HTTPS probe below (a healthy site reads as down).
# (Left to the OS when it already decides: SystemDefault includes TLS 1.2 and 1.3.)
if ([Net.ServicePointManager]::SecurityProtocol -ne [Net.SecurityProtocolType]::SystemDefault) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
$script:fail = 0
$script:warn = 0
$cfg = $null
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
            # BUG-140: inside means the same folder or under it (D:\inetpub\casebookdata isn't inside D:\inetpub\casebook).
            if ($dr -ieq $sp -or $dr.ToLower().StartsWith($sp.ToLower() + '\')) { Bad "DataRoot '$dr' is inside SitePath '$sp' - keep case evidence OFF the web root" }
            else { Ok "SitePath and DataRoot are separate" }
        }
        foreach ($p in @($cfg.SitePath, $cfg.DataRoot)) {
            if ([string]::IsNullOrWhiteSpace([string]$p)) { continue }
            $root = [System.IO.Path]::GetPathRoot([string]$p)
            if ($root -and (Test-Path $root)) { Ok "Drive $root present (for $p)" }
            else { Warn "Drive $root for '$p' not found here (fine if you're not on the web host; the installer creates the folders, not the volume)" }
        }

        # --- Integrity keys (F-23/F-25) ---
        $sigSource = if ($cfg.ContainsKey('SigningKeySource') -and $cfg.SigningKeySource) { [string]$cfg.SigningKeySource } else { 'File' }
        $chainSource = if ($cfg.ContainsKey('ChainKeySource')) { [string]$cfg.ChainKeySource } else { '' }
        function Test-KeyCert([string] $thumb, [string] $what) {
            $tp = ($thumb -replace '[^0-9A-Fa-f]','').ToUpper()
            if (-not $tp) { Bad "$what uses a certificate but its thumbprint is empty"; return }
            $c = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $tp }
            if (-not $c) { Warn "$what certificate $tp not found in LocalMachine\My here (must be on the web host)" }
            elseif (-not $c.HasPrivateKey) { Bad "$what certificate $tp has no private key" }
            elseif (-not [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($c)) { Bad "$what certificate $tp isn't RSA" }
            else { Ok "$what certificate $tp present with a private key" }
        }
        function Test-KeySecret([string] $ref, [string] $what) {
            if ($ref -notmatch '^\s*@cyberark:') { Bad "$what must be an @cyberark:Safe=...;Object=... reference (the key itself never goes in config)" }
            else { Ok "$what is a CyberArk reference (resolved at startup; check Administration -> Diagnostics)" }
        }
        switch ($sigSource) {
            'File'             { Info "Seal signing key: a file at <DataRoot>\keys\seal-signing.pem (provision it out of band)" }
            'CertificateStore' { Test-KeyCert ([string]$cfg.SigningKeyThumbprint) 'Seal signing key' }
            'CyberArk'         { Test-KeySecret ([string]$cfg.SigningKeySecret) 'SigningKeySecret' }
            default            { Bad "SigningKeySource '$sigSource' isn't File, CertificateStore or CyberArk" }
        }
        switch ($chainSource) {
            ''            { Info "Audit chain key: off (the default)" }
            'Certificate' { Test-KeyCert ([string]$cfg.ChainKeyThumbprint) 'Audit chain key' }
            'CyberArk'    { Test-KeySecret ([string]$cfg.ChainKeySecret) 'ChainKeySecret' }
            default       { Bad "ChainKeySource '$chainSource' isn't '', CyberArk or Certificate" }
        }

        # --- Evidence encryption at rest (PROD-57) ---
        $encOn = $cfg.ContainsKey('EvidenceEncryption') -and [bool]$cfg.EvidenceEncryption
        $recList = @()
        if ($cfg.ContainsKey('RecoveryCertificates')) { $recList = @($cfg.RecoveryCertificates | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) }
        if (-not $encOn) { Info "Evidence encryption: off (the default)" }
        else {
            # What protects the key: its own certificate, else the integrity certificate, else the CyberArk chain key.
            $ownThumb = if ($cfg.ContainsKey('EvidenceKeyThumbprint')) { [string]$cfg.EvidenceKeyThumbprint } else { '' }
            if ($ownThumb -replace '[^0-9A-Fa-f]','') { Test-KeyCert $ownThumb 'Evidence key' }
            elseif ($chainSource -eq 'Certificate') { Ok "Evidence key: protected by the audit chain key's certificate (checked above)" }
            elseif ($sigSource -eq 'CertificateStore') { Ok "Evidence key: protected by the seal-signing certificate (checked above)" }
            elseif ($chainSource -eq 'CyberArk') { Ok "Evidence key: protected by a key derived from the CyberArk chain key" }
            else { Bad "Evidence encryption is on but nothing can protect its key: set EvidenceKeyThumbprint, or use a certificate (or CyberArk) for the signing or chain key" }
            if (-not $recList.Count) { Warn "Evidence encryption is on with no RecoveryCertificates: nothing is encrypted until shares are issued (casebook-keytool split) after install" }
            $evPath = if ($cfg.ContainsKey('EvidencePath') -and $cfg.EvidencePath) { [string]$cfg.EvidencePath } else { '' }
            if ($evPath.StartsWith('\\')) { Info "Evidence store on a share: the key's envelope copy is kept there too (.key folder); back the share up with the database and the keys folder" }
        }
        foreach ($rp in $recList) {
            if (-not (Test-Path $rp)) { Bad "Recovery certificate '$rp' not found"; continue }
            try { $rc = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (Resolve-Path $rp).Path }
            catch { Bad "Recovery certificate '$rp' couldn't be read as a public certificate (a password-protected .pfx holds the private key: give the exported .cer instead)"; continue }
            if ($rc.HasPrivateKey) { Bad "Recovery certificate '$rp' contains its private key: give the public part only (.cer) and keep the private key offline"; continue }
            if (-not [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($rc)) { Bad "Recovery certificate '$rp' isn't RSA"; continue }
            $days = ($rc.NotAfter - (Get-Date)).TotalDays
            if ($days -lt 0) { Warn "Recovery certificate $($rc.Thumbprint) expired $($rc.NotAfter.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)) (it still recovers the key; renew it when convenient)" }
            else { Ok "Recovery certificate $($rc.Thumbprint) ($($rc.Subject)), public part only" }
        }
        if ($recList.Count -eq 1) { Warn "One recovery certificate: two, with two custodians, is the recommended setup" }

        # --- TLS certificate ---
        if ($cfg.ContainsKey('CertificateThumbprint') -and -not [string]::IsNullOrWhiteSpace([string]$cfg.CertificateThumbprint)) {
            $tp = (([string]$cfg.CertificateThumbprint) -replace '\s','').ToUpper()
            $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $tp }
            if (-not $cert) {
                Warn "Cert $tp not found in LocalMachine\My here (must be present on the web host for the 443 binding)"
            } elseif (-not $cert.HasPrivateKey) {
                Bad "Cert $tp has no private key - IIS can't bind TLS with it"
            } elseif ($cert.NotAfter -lt (Get-Date)) {
                Bad "Cert $tp EXPIRED $($cert.NotAfter.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture))"
            } elseif ($cert.NotAfter -lt (Get-Date).AddDays(30)) {
                Warn "Cert $tp valid but expires soon ($($cert.NotAfter.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)))"
            } else {
                Ok "Cert $tp present, has private key, valid to $($cert.NotAfter.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture))"
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
        if (Test-AspNetCoreModule) { Ok "ASP.NET Core Module present (this host can host the app)" }
        else { Warn ".NET 10 Hosting Bundle / ASP.NET Core Module not found (install it on the WEB host before Install-CaseBook)" }
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
        # BUG-95/137: one CaseBook process at a time, and no scheduled recycle.
        $recycling = (Get-Item "IIS:\AppPools\$pool").recycling
        if ($recycling.disallowOverlappingRotation) { Ok "App pool '$pool' never runs two processes at once" }
        else { Warn "App pool '$pool' allows overlapped recycling: two CaseBook processes run side by side during a recycle. Set recycling.disallowOverlappingRotation (Upgrade-CaseBook.ps1 does)." }
        if ($recycling.periodicRestart.time -eq [TimeSpan]::Zero) { Ok "App pool '$pool' has no scheduled recycle" }
        else { Warn "App pool '$pool' recycles every $($recycling.periodicRestart.time). Set recycling.periodicRestart.time to 00:00:00 (Upgrade-CaseBook.ps1 does)." }
    } catch { Bad "Could not read app pool '$pool': $($_.Exception.Message)" }

    # 2. HTTP reachability over Windows auth
    # BUG-336: the app answers 400 to a host name AllowedHosts doesn't list (and IIS to one no binding has): an IP or
    # localhost URL reads as broken although the site works by its name.
    $hostHint = ("400 Bad Request for host '$(([Uri]$Url).Host)': it isn't in AllowedHosts (appsettings.Production.json) " +
                 "or on a binding of the site. Use the site's host name in -Url, or add this one to AllowedHosts (';' separated).")
    try {
        Info "GET $Url (Windows integrated auth)"
        $resp = Invoke-WebRequest -Uri $Url -UseDefaultCredentials -UseBasicParsing -TimeoutSec 30
        if ($resp.StatusCode -eq 200) { Ok "Site responded 200 OK" }
        else { Bad "Unexpected status $($resp.StatusCode)" }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__ 2>$null
        if ($code -eq 401) { Bad "401 Unauthorized - Windows auth not negotiating (check SPNs / that you're a mapped role member)" }
        elseif ($code -eq 400) { Bad $hostHint }
        else { Bad "Request failed: $($_.Exception.Message)" }
    }

    # 3. BUG-261: /api reaches the app. The installer opens /api to anonymous requests (API tokens), and IIS can answer
    #    there itself: a web.config whose handler sits in <location inheritInChildApplications="false"> leaves /api to
    #    IIS's StaticFile handler, which answers 404, so API imports never arrive. Asked directly (no proxy).
    $schemaUrl = ([Uri]$Url).GetLeftPart([UriPartial]::Authority) + '/api/import/cases/schema'
    Info "GET $schemaUrl (anonymous)"
    $prevCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {
        $req = [System.Net.HttpWebRequest]::Create($schemaUrl)
        $req.Proxy = $null; $req.AllowAutoRedirect = $false; $req.Timeout = 30000
        $r = $null
        try { $r = $req.GetResponse() } catch {
            $ex = $_.Exception; while ($ex -and $ex -isnot [System.Net.WebException]) { $ex = $ex.InnerException }
            if ($ex -and $ex.Response) { $r = $ex.Response } else { throw }
        }
        try {
            $code = [int]$r.StatusCode
            $body = (New-Object System.IO.StreamReader($r.GetResponseStream())).ReadToEnd()
        } finally { $r.Close() }
        if ($code -eq 200 -and $body -match '"\$schema"') { Ok "/api reaches CaseBook (API imports can arrive)" }
        elseif ($code -eq 404) {
            Bad ("/api answered 404 from IIS, not CaseBook: API imports can't reach the app. The site's web.config probably " +
                 "wraps its handler in <location inheritInChildApplications=""false"">; upgrade to v1.6.2 or later, or set it to ""true"".")
        }
        elseif ($code -eq 400) { Bad "/api answered $hostHint" }
        elseif ($code -in 401,403) { Bad "/api answered ${code}: it isn't open to anonymous requests, so API tokens can't sign in (re-run Install-CaseBook.ps1)." }
        else { Bad "/api answered $code, not the import schema." }
    } catch { Bad "/api request failed: $($_.Exception.Message)" }
    finally { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCallback }

    # 4. CAP-37: the app's other anonymous endpoints reach it without a sign-in. The installer carves them out of
    #    Windows Auth; a 401 or 403 here is IIS refusing before the app runs. Asked directly (no proxy), no credentials.
    #    /health/live answers the status word; the logo is the image or the app's 404 (none configured); the agenda
    #    feed without a token is the app's 404, which proves the path reaches it and that it still wants its token.
    $siteRoot = ([Uri]$Url).GetLeftPart([UriPartial]::Authority)
    $anonChecks = @(
        @{ Path = '/health/live';     Want = @(200);      What = 'load-balancer and uptime probes' },
        @{ Path = '/branding/logo';   Want = @(200, 404); What = 'the logo in branded emails' },
        @{ Path = '/agenda/feed.ics'; Want = @(404);      What = 'calendar subscriptions' }
    )
    $prevCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {
        foreach ($c in $anonChecks) {
            $probe = $siteRoot + $c.Path
            Info "GET $probe (anonymous)"
            try {
                $req = [System.Net.HttpWebRequest]::Create($probe)
                $req.Proxy = $null; $req.AllowAutoRedirect = $false; $req.Timeout = 30000
                $r = $null
                try { $r = $req.GetResponse() } catch {
                    $ex = $_.Exception; while ($ex -and $ex -isnot [System.Net.WebException]) { $ex = $ex.InnerException }
                    if ($ex -and $ex.Response) { $r = $ex.Response } else { throw }
                }
                try {
                    $code = [int]$r.StatusCode
                    $body = (New-Object System.IO.StreamReader($r.GetResponseStream())).ReadToEnd()
                } finally { $r.Close() }
                if ($code -in 401,403) {
                    Bad ("$($c.Path) answered ${code}: IIS isn't letting anonymous requests through, so $($c.What) fail. " +
                         "Re-run Install-CaseBook.ps1 (it carves the path out of Windows Auth).")
                }
                elseif ($code -eq 400) { Bad "$($c.Path) answered $hostHint" }
                elseif ($c.Path -eq '/health/live' -and $code -eq 200 -and $body.Trim() -ne 'Healthy') {
                    Bad "$($c.Path) answered 200 but not CaseBook's status word."
                }
                elseif ($code -in $c.Want) { Ok "$($c.Path) reaches CaseBook anonymously ($($c.What))" }
                else { Bad "$($c.Path) answered $code, not what CaseBook answers there." }
            } catch { Bad "$($c.Path) request failed: $($_.Exception.Message)" }
        }
    } finally { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCallback }
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
