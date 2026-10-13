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

function Publish-CaseBookDeployScripts([string] $SourceDeployDir, [string] $SitePath) {
    # PROD-50: keep a copy of the deploy scripts beside the site (<site parent>\CaseBook-deploy), so the next upgrade is
    # one command (Upgrade-CaseBook.ps1 -Version vX.Y.Z) and Administration > Updates can show it. Administrators and
    # SYSTEM may change the folder; everyone else, the app-pool identity included, may only read it. Never the data
    # root: the app pool can write there, and these scripts are run elevated. Returns the folder, or $null.
    $target = Join-Path (Split-Path -Parent $SitePath) 'CaseBook-deploy'
    if (-not (Test-Path (Join-Path $SourceDeployDir 'Upgrade-CaseBook.ps1'))) { return $null }
    if ((Resolve-Path $SourceDeployDir).Path.TrimEnd('\') -ieq $target.TrimEnd('\')) { return $target }   # running from it
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    & robocopy $SourceDeployDir $target /MIR /R:2 /W:2 /NFL /NDL /NJH /NJS /NP | Out-Null
    # robocopy reports success when it can't read the target at all, so check the copy landed.
    if ($LASTEXITCODE -ge 8 -or -not (Test-Path (Join-Path $target 'Upgrade-CaseBook.ps1'))) {
        throw "Copying the deploy scripts to $target failed (robocopy exit $LASTEXITCODE)."
    }

    # Then lock it down; Set-Acl passes the inheritable rules on to what was just copied.
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none    = [System.Security.AccessControl.PropagationFlags]::None
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)   # no inherited rights
    foreach ($r in @(@('S-1-5-32-544', 'FullControl'), @('S-1-5-18', 'FullControl'), @('S-1-5-11', 'ReadAndExecute'))) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($r[0])   # Administrators, SYSTEM, Authenticated Users
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $r[1], $inherit, $none, 'Allow')))
    }
    Set-Acl -Path $target -AclObject $acl
    return $target
}
