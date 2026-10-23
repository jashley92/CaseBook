# IIS helpers shared by Install-CaseBook.ps1 and Upgrade-CaseBook.ps1.
#
# REV-71/REV-72: Stop-WebAppPool only asks the pool to stop. Its worker (w3wp) finishes open requests, Blazor circuits
# and background jobs first, and holds the app's DLLs until it exits, so copying files straight after (a fixed few
# seconds' wait) fails on locked files part way through.

function Stop-CaseBookAppPool([string] $Name, [int] $TimeoutSeconds = 120) {
    # Stops the pool and waits until it reports Stopped and its worker process has exited. Throws if it doesn't in time.
    Import-Module WebAdministration -ErrorAction Stop
    if (-not (Test-Path "IIS:\AppPools\$Name")) { return }
    if ((Get-WebAppPoolState -Name $Name).Value -ne 'Stopped') { Stop-WebAppPool -Name $Name }
    $pattern = '-ap\s+"' + [regex]::Escape($Name) + '"'
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $state = (Get-WebAppPoolState -Name $Name).Value
        $workers = @(Get-CimInstance Win32_Process -Filter "Name = 'w3wp.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -match $pattern })
        if ($state -eq 'Stopped' -and $workers.Count -eq 0) { return }
        Start-Sleep -Seconds 2
    }
    throw ("The app pool '$Name' didn't stop within $TimeoutSeconds seconds: its worker process still holds the app's " +
           "files. Stop the pool in IIS Manager (or end its w3wp.exe), then re-run.")
}

# PROD-34 / CAP-37: the paths IIS lets through to the app without a Windows sign-in. The rest of the site stays Windows-
# authenticated. The app still enforces each one: /api takes a bearer token; /health (and /health/live, /health/ready,
# /health/alarms below it) answers a status word only, with no detail; /branding/logo is the branding image only; the
# agenda feed is 404 without a valid signed token in its URL. /agenda/agenda.ics (the signed-in download) is NOT here.
# The one list: Install-CaseBook.ps1 sets these and Upgrade-CaseBook.ps1 checks and repairs them.
function Get-CaseBookAnonymousPaths { return @('api', 'health', 'branding/logo', 'agenda/feed.ics') }

# Each carve-out is two <location> settings, applied in this order: anonymous on, then Windows off.
function Get-CaseBookCarveOutSettings {
    return @(
        [pscustomobject]@{ Section = 'anonymousAuthentication'; Enabled = 'true'  },
        [pscustomobject]@{ Section = 'windowsAuthentication';   Enabled = 'false' }
    )
}

function Get-CaseBookAnonymousPathPurpose([string] $Path) {
    switch ($Path) {
        'api'             { return 'the token-authenticated API (API tokens, imports, IOC feeds)' }
        'health'          { return 'the health probes to load balancers and monitors' }
        'branding/logo'   { return 'the email logo to mail clients' }
        'agenda/feed.ics' { return 'calendar subscriptions to calendar apps' }
        default           { return "the app's anonymous endpoint /$Path" }
    }
}

function Get-CaseBookLocationAuth([string] $SiteName, [string] $Path, [string] $Section) {
    # The 'enabled' value IIS applies at <site>/<path>: its <location> entry's, or the one inherited from the site when
    # there is none. 'true', 'false', or $null when it can't be read. Reading is allowed although the section is locked.
    Import-Module WebAdministration -ErrorAction Stop
    try {
        $v = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location "$SiteName/$Path" `
            -Filter "system.webServer/security/authentication/$Section" -Name 'enabled' -ErrorAction Stop
    } catch { return $null }
    if ($null -eq $v) { return $null }
    if ($v.PSObject.Properties['Value']) { $v = $v.Value }   # a ConfigurationAttribute, or the bare value
    $s = ([string]$v).Trim().ToLowerInvariant()
    if ($s -eq 'true' -or $s -eq 'false') { return $s }
    return $null
}

function Sync-CaseBookAnonymousCarveOuts {
    # Makes each path in Get-CaseBookAnonymousPaths anonymous on, Windows off, at <site>/<path>, with appcmd and
    # /commit:apphost: the authentication sections are LOCKED at server scope, so the WebAdministration cmdlets throw
    # 0x8007000D writing them for a site, while a <location> entry in applicationHost.config is allowed.
    #   -SetAlways : write every setting without reading it first (the installer).
    #   -DryRun    : read only and report what would change (the upgrade's preflight and -WhatIf).
    # Returns one object per path: Path, State ('ok', 'configured' or 'would-configure') and Changes (what differed, as
    # "section: was -> now"). Throws on a failed write, naming the fix and what had already been changed.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $SiteName,
        [string] $Appcmd = (Join-Path $env:WINDIR 'System32\inetsrv\appcmd.exe'),
        [switch] $SetAlways,
        [switch] $DryRun
    )
    if (-not $DryRun -and -not (Test-Path $Appcmd)) {
        throw "appcmd.exe not found at $Appcmd - is the IIS 'Web-Server' role installed?"
    }
    # appcmd reports a failure in its output and exit code; under a caller's 'Stop' a line on stderr would otherwise end
    # the run with the bare text before the message below could say what to do.
    $ErrorActionPreference = 'Continue'
    $results = @()
    $done = @()
    foreach ($p in (Get-CaseBookAnonymousPaths)) {
        $changes = @()
        foreach ($s in (Get-CaseBookCarveOutSettings)) {
            $was = $null
            if (-not $SetAlways) {
                $was = Get-CaseBookLocationAuth -SiteName $SiteName -Path $p -Section $s.Section
                if ($was -eq $s.Enabled) { continue }
            }
            $wasText = if ($SetAlways) { 'set' } elseif ($null -eq $was) { 'unreadable' } else { $was }
            $changes += "$($s.Section): $wasText -> $($s.Enabled)"
            if ($DryRun) { continue }
            $out = & $Appcmd set config "$SiteName/$p" `
                "/section:system.webServer/security/authentication/$($s.Section)" `
                "/enabled:$($s.Enabled)" /commit:apphost 2>&1
            if ($LASTEXITCODE -ne 0) {
                $already = if ($done.Count -gt 0) { " Already changed: $($done -join '; ')." } else { '' }
                throw ("Failed to set $($s.Section) on '$SiteName/$p' (appcmd exit $LASTEXITCODE): $out. This opens " +
                       "$(Get-CaseBookAnonymousPathPurpose $p) without a Windows sign-in.$already Fix: run elevated, and " +
                       "make sure the IIS authentication role services are installed (anonymous authentication comes with " +
                       "the Web-Server role; Install-WindowsFeature Web-Server, Web-Windows-Auth -IncludeManagementTools), " +
                       "then re-run. By hand: appcmd set config ""$SiteName/$p"" /section:system.webServer/security/" +
                       "authentication/$($s.Section) /enabled:$($s.Enabled) /commit:apphost")
            }
            $done += "/$p $($s.Section) -> $($s.Enabled)"
        }
        $state = if ($changes.Count -eq 0) { 'ok' } elseif ($DryRun) { 'would-configure' } else { 'configured' }
        $results += [pscustomobject]@{ Path = "/$p"; State = $state; Changes = $changes }
    }
    return $results
}

function Get-CaseBookAppPoolSid([string] $SiteName) {
    # The SID the site's app pool runs as, or $null when the site, pool or account can't be resolved.
    try {
        if (-not $SiteName -or -not (Test-Path "IIS:\Sites\$SiteName")) { return $null }
        $pool = (Get-ItemProperty "IIS:\Sites\$SiteName" -Name applicationPool)
        if ($pool -isnot [string]) { $pool = $pool.Value }
        if (-not $pool) { return $null }
        $type = [string](Get-ItemProperty "IIS:\AppPools\$pool" -Name processModel.identityType)
        switch ($type) {
            'LocalSystem'    { return New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18') }
            'LocalService'   { return New-Object System.Security.Principal.SecurityIdentifier('S-1-5-19') }
            'NetworkService' { return New-Object System.Security.Principal.SecurityIdentifier('S-1-5-20') }
            'SpecificUser'   { $account = [string](Get-ItemProperty "IIS:\AppPools\$pool" -Name processModel.userName) }
            default          { $account = "IIS AppPool\$pool" }   # ApplicationPoolIdentity
        }
        if (-not $account) { return $null }
        return (New-Object System.Security.Principal.NTAccount($account)).Translate([System.Security.Principal.SecurityIdentifier])
    } catch { return $null }
}

function Publish-CaseBookDeployScripts([string] $SourceDeployDir, [string] $SitePath, [string] $SiteName) {
    # PROD-50: keep a copy of the deploy scripts beside the site (<site parent>\<site folder>-deploy), so the next upgrade is
    # one command (Upgrade-CaseBook.ps1 -Version vX.Y.Z) and Administration > Updates can show it. Administrators and
    # SYSTEM may change the folder; the site's app-pool identity may only read it, and no one else may open it (BUG-704:
    # it holds the answers file, which names the AD role groups, SQL host and service accounts). Never the data
    # root: the app pool can write there, and these scripts are run elevated. Returns the folder, or $null.
    # WF-71: one folder per site (C:\inetpub\CaseBook -> CaseBook-deploy), so two sites under one parent don't share it, and
    # site.txt names the IIS site, so the command Administration > Updates shows upgrades this site and no other.
    $site = $SitePath.TrimEnd([char]92)
    $target = Join-Path (Split-Path -Parent $site) "$(Split-Path -Leaf $site)-deploy"
    if (-not (Test-Path (Join-Path $SourceDeployDir 'Upgrade-CaseBook.ps1'))) { return $null }
    if ((Resolve-Path $SourceDeployDir).Path.TrimEnd('\') -ieq $target.TrimEnd('\')) { return $target }   # running from it
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    & robocopy $SourceDeployDir $target /MIR /R:2 /W:2 /NFL /NDL /NJH /NJS /NP | Out-Null
    # robocopy reports success when it can't read the target at all, so check the copy landed.
    if ($LASTEXITCODE -ge 8 -or -not (Test-Path (Join-Path $target 'Upgrade-CaseBook.ps1'))) {
        throw "Copying the deploy scripts to $target failed (robocopy exit $LASTEXITCODE)."
    }
    if ($SiteName) { Set-Content -Path (Join-Path $target 'site.txt') -Value "Site: $SiteName" -Encoding ascii }

    # Then lock it down; Set-Acl passes the inheritable rules on to what was just copied.
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none    = [System.Security.AccessControl.PropagationFlags]::None
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)   # no inherited rights
    foreach ($r in @(@('S-1-5-32-544', 'FullControl'), @('S-1-5-18', 'FullControl'))) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($r[0])   # Administrators, SYSTEM
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $r[1], $inherit, $none, 'Allow')))
    }
    $poolSid = Get-CaseBookAppPoolSid -SiteName $SiteName
    if ($poolSid) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($poolSid, 'ReadAndExecute', $inherit, $none, 'Allow')))
    } else {
        Write-Warning "Couldn't resolve the app-pool identity for site '$SiteName'; $target is readable by Administrators and SYSTEM only."
    }
    Set-Acl -Path $target -AclObject $acl
    return $target
}

function Update-CaseBookTaskPaths([string] $KeptDir, [string] $SitePath) {
    # A task registered from a release folder (Backup-CaseBook.ps1 -Register and the like) runs that folder's copy of the
    # script, and fails once the folder is gone. Point this site's CaseBook tasks at the kept copy, which every upgrade
    # refreshes. Only tasks whose arguments name this site (-SitePath) are touched, so another site's are left alone.
    if (-not $KeptDir -or -not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) { return }
    $site = $SitePath.TrimEnd([char]92)
    foreach ($task in @(Get-ScheduledTask -TaskName 'CaseBook *' -ErrorAction SilentlyContinue)) {
        $action = @($task.Actions)[0]
        if (-not $action -or -not $action.Arguments) { continue }
        if ($action.Arguments -notmatch ('-SitePath "' + [regex]::Escape($site) + '[\\]?"')) { continue }
        if ($action.Arguments -notmatch '-File "([^"]+[.]ps1)"') { continue }
        $file = $Matches[1]
        $want = Join-Path $KeptDir (Split-Path -Leaf $file)
        if ($file -ieq $want -or -not (Test-Path $want)) { continue }
        try {
            $new = New-ScheduledTaskAction -Execute $action.Execute -Argument $action.Arguments.Replace("-File `"$file`"", "-File `"$want`"")
            Set-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Action $new -ErrorAction Stop | Out-Null
            Write-Host "    Scheduled task '$($task.TaskName)' now runs $want (it ran $file)." -ForegroundColor Gray
        } catch {
            Write-Host "    Scheduled task '$($task.TaskName)' runs $file, which upgrades don't refresh, and couldn't be changed ($($_.Exception.Message)). Run its script's -Register again from $KeptDir." -ForegroundColor Yellow
        }
    }
}
